package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Macmod/godap/v2/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

func createTreeNodeFromEntry(entry *ldap.Entry) *tview.TreeNode {
	_, ok := explorerCache.Get(entry.DN)

	if !ok {
		nodeName := getNodeName(entry)

		node := tview.NewTreeNode(nodeName).
			SetReference(entry.DN).
			SetSelectable(true)

		// Helpful node coloring for deleted and disabled objects
		if colors {
			color, changed := utils.GetEntryColor(entry)
			if changed {
				node.SetColor(color)
			}
		}

		explorerCache.Add(entry.DN, entry)

		node.SetExpanded(false)
		return node
	} else {
		return nil
	}
}

// Unloads child nodes and their attributes from the cache
func unloadChildren(parentNode *tview.TreeNode) {
	var children []*tview.TreeNode
	parentNode.Walk(func(node, parent *tview.TreeNode) bool {
		if node.GetReference() != parentNode.GetReference() {
			children = append(children, node)
		}
		return true
	})

	for _, child := range children {
		childDN := child.GetReference().(string)
		explorerCache.Delete(childDN)
		parentNode.RemoveChild(child)
	}
}

// Loads child nodes and their attributes directly from LDAP
func loadChildren(node *tview.TreeNode) {
	baseDN := node.GetReference().(string)
	entries, err := lc.Query(baseDN, searchFilter, ldap.ScopeSingleLevel, deleted)
	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		return
	}

	// Sort results to guarantee stable view
	sort.Slice(entries, func(i int, j int) bool {
		return getName(entries[i]) < getName(entries[j])
	})

	for _, entry := range entries {
		childNode := createTreeNodeFromEntry(entry)

		if childNode != nil {
			node.AddChild(childNode)
		}
	}
}

func handleAttrsKeyCtrlE(currentNode *tview.TreeNode, attrsPanel *tview.Table, cache *EntryCache) {
	currentFocus := app.GetFocus()
	attrRow, _ := attrsPanel.GetSelection()
	attrName := attrsPanel.GetCell(attrRow, 0).Text

	baseDN := currentNode.GetReference().(string)

	entry, _ := cache.Get(baseDN)
	attrVals := entry.GetAttributeValues(attrName)
	if len(attrVals) == 0 {
		return
	}

	// Encode attribute values to hex
	rawAttrVals := entry.GetRawAttributeValues(attrName)

	var attrValsHex []string
	for idx := range rawAttrVals {
		hexEncoded := hex.EncodeToString(rawAttrVals[idx])
		attrValsHex = append(attrValsHex, hexEncoded)
	}

	valIndices := []string{}
	for idx := range attrVals {
		valIndices = append(valIndices, strconv.Itoa(idx))
	}
	valIndices = append(valIndices, "New")

	selectedIndex := 0

	useHexEncoding := false

	writeAttrValsForm := NewXForm()
	writeAttrValsForm.
		AddTextView("Base DN", baseDN, 0, 1, false, true).
		AddTextView("Attribute Name", attrName, 0, 1, false, true).
		AddTextView("Current Value", attrVals[0], 0, 1, false, true).
		AddTextView("Current Value (HEX)", attrValsHex[0], 0, 1, false, true).
		AddDropDown("Value Index", valIndices, 0, func(option string, optionIndex int) {
			selectedIndex = optionIndex

			currentValItem := writeAttrValsForm.GetFormItemByLabel("Current Value").(*tview.TextView)
			currentValItemHex := writeAttrValsForm.GetFormItemByLabel("Current Value (HEX)").(*tview.TextView)

			if selectedIndex < len(attrVals) {
				currentValItem.SetText(attrVals[selectedIndex])
				currentValItemHex.SetText(attrValsHex[selectedIndex])
			} else {
				currentValItem.SetText("")
				currentValItemHex.SetText("")
			}
		}).
		AddInputField("New Value", "", 0, nil, nil).
		AddCheckbox("Use HEX encoding", false, func(checked bool) {
			useHexEncoding = checked
		}).
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		}).
		AddButton("Update", func() {
			newValue := writeAttrValsForm.GetFormItemByLabel("New Value").(*tview.InputField).GetText()
			if useHexEncoding {
				newValueBytes, err := hex.DecodeString(newValue)
				if err == nil {
					newValue = string(newValueBytes)
				} else {
					updateLog(fmt.Sprint(err), "red")
					return
				}
			}

			if selectedIndex < len(attrVals) {
				attrVals[selectedIndex] = newValue
			} else {
				attrVals = append(attrVals, newValue)
			}

			err := lc.ModifyAttribute(baseDN, attrName, attrVals)
			// TODO: Don't go back immediately so that the user can
			// change multiple values at once
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
			} else {
				updateLog("Attribute updated: '"+attrName+"' from '"+baseDN+"'", "green")
			}

			reloadAttributesPanel(currentNode, attrsPanel, false, cache)

			/*
				if parentNode != nil {
					idx := findEntryInChildren(baseDN, parentNode)

					parent := reloadParentNode(currentNode)
					siblings := parent.GetChildren()

					tree.SetCurrentNode(siblings[idx])
				} else {
					// Update UI in this edge case
				}
			*/

			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		})

	writeAttrValsForm.
		SetButtonBackgroundColor(formButtonBackgroundColor).
		SetButtonTextColor(formButtonTextColor).
		SetButtonActivatedStyle(formButtonActivatedStyle)
	writeAttrValsForm.SetInputCapture(handleEscapeToTree)
	writeAttrValsForm.SetTitle("Attribute Editor").SetBorder(true)
	app.SetRoot(writeAttrValsForm, true).SetFocus(writeAttrValsForm)
}

func handleAttrsKeyDelete(currentNode *tview.TreeNode, attrsPanel *tview.Table, cache *EntryCache) {
	currentFocus := app.GetFocus()
	baseDN := currentNode.GetReference().(string)

	attrRow, _ := attrsPanel.GetSelection()
	attrName := attrsPanel.GetCell(attrRow, 0).Text

	promptModal := tview.NewModal().
		SetText("Do you really want to delete attribute `" + attrName + "` of this object?\n" + baseDN).
		AddButtons([]string{"No", "Yes"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				err := lc.DeleteAttribute(baseDN, attrName)
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				} else {
					cache.Delete(baseDN)
					reloadAttributesPanel(currentNode, attrsPanel, false, cache)

					updateLog("Attribute deleted: "+attrName+" from "+baseDN, "green")
				}
			}

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		})

	app.SetRoot(promptModal, false).SetFocus(promptModal)
}

func handleAttrsKeyCtrlN(currentNode *tview.TreeNode, attrsPanel *tview.Table, cache *EntryCache) {
	currentFocus := app.GetFocus()
	createAttrForm := NewXForm().
		SetButtonBackgroundColor(formButtonBackgroundColor).
		SetButtonTextColor(formButtonTextColor).
		SetButtonActivatedStyle(formButtonActivatedStyle)
	createAttrForm.SetInputCapture(handleEscapeToTree)

	baseDN := currentNode.GetReference().(string)

	createAttrForm.
		AddTextView("Object DN", baseDN, 0, 1, false, true).
		AddInputField("Attribute Name", "", 20, nil, nil).
		AddInputField("Attribute Value", "", 20, nil, nil).
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		}).
		AddButton("Create", func() {
			attrName := createAttrForm.GetFormItemByLabel("Attribute Name").(*tview.InputField).GetText()
			attrVal := createAttrForm.GetFormItemByLabel("Attribute Value").(*tview.InputField).GetText()

			err := lc.AddAttribute(baseDN, attrName, []string{attrVal})
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
			} else {
				cache.Delete(baseDN)
				reloadAttributesPanel(currentNode, attrsPanel, false, cache)

				updateLog("Attribute added: "+attrName+" to "+baseDN, "green")
			}

			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		}).
		SetTitle("Attribute Creator").
		SetBorder(true)

	app.SetRoot(createAttrForm, true).SetFocus(createAttrForm)
}

func handleAttrsKeyDown(attrsPanel *tview.Table) {
	selectedRow, selectedCol := attrsPanel.GetSelection()
	rowCount := attrsPanel.GetRowCount()

	if selectedCol == 0 {
		s := selectedRow + 1
		for s < rowCount && attrsPanel.GetCell(s, 0).Text == "" {
			s = s + 1
		}

		if s == rowCount {
			attrsPanel.Select(selectedRow-1, 0)
		} else if s != selectedRow {
			attrsPanel.Select(s-1, 0)
		}
	}
}

func handleAttrsKeyUp(attrsPanel *tview.Table) {
	selectedRow, selectedCol := attrsPanel.GetSelection()
	if selectedCol == 0 {
		s := selectedRow - 1
		for s > 0 && attrsPanel.GetCell(s, 0).Text == "" {
			s = s - 1
		}

		if s != selectedRow {
			attrsPanel.Select(s+1, 0)
		}
	}
}

func attrsPanelKeyHandler(event *tcell.EventKey, currentNode *tview.TreeNode, cache *EntryCache, attrsPanel *tview.Table) *tcell.EventKey {
	switch event.Rune() {
	case 'r', 'R':
		baseDN := currentNode.GetReference().(string)

		updateLog("Reloading node "+baseDN, "yellow")

		cache.Delete(baseDN)
		reloadAttributesPanel(currentNode, attrsPanel, false, cache)

		updateLog("Node "+baseDN+" reloaded", "green")

		go func() {
			app.Draw()
		}()
		return event
	}

	switch event.Key() {
	case tcell.KeyDelete:
		handleAttrsKeyDelete(currentNode, attrsPanel, cache)
	case tcell.KeyCtrlE:
		handleAttrsKeyCtrlE(currentNode, attrsPanel, cache)
	case tcell.KeyCtrlN:
		handleAttrsKeyCtrlN(currentNode, attrsPanel, cache)
	case tcell.KeyDown:
		handleAttrsKeyDown(attrsPanel)
	case tcell.KeyUp:
		handleAttrsKeyUp(attrsPanel)
	}

	return event
}

func reloadAttributesPanel(node *tview.TreeNode, attrsTable *tview.Table, useCache bool, cache *EntryCache) error {
	ref := node.GetReference()
	if ref == nil {
		return fmt.Errorf("Couldn't reload attributes: no node selected")
	}

	var attributes []*ldap.EntryAttribute

	baseDN := ref.(string)

	attrsTable.Clear()

	if useCache {
		entry, ok := cache.Get(baseDN)
		if ok {
			attributes = entry.Attributes
		} else {
			return fmt.Errorf("Couldn't reload attributes: node not cached")
		}
	} else {
		entries, err := lc.Query(baseDN, searchFilter, ldap.ScopeBaseObject, deleted)
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return err
		}

		if len(entries) != 1 {
			return fmt.Errorf("Entry not found")
		}

		entry := entries[0]
		cache.Add(baseDN, entry)

		attributes = entry.Attributes
	}

	row := 0
	for _, attribute := range attributes {
		var cellName string = attribute.Name

		var cellValues []string

		attrsTable.SetCell(row, 0, tview.NewTableCell(cellName))

		if formatAttrs {
			cellValues = utils.FormatLDAPAttribute(attribute, timeFormat)
		} else {
			cellValues = attribute.Values
		}

		if !expandAttrs {
			myCell := tview.NewTableCell(strings.Join(cellValues, "; "))

			if colors {
				color, ok := utils.GetAttrCellColor(cellName, attribute.Values[0])
				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			attrsTable.SetCell(row, 1, myCell)
			row = row + 1
			continue
		}

		for idx, cellValue := range cellValues {
			myCell := tview.NewTableCell(cellValue)

			if colors {
				var refValue string
				if !expandAttrs || len(cellValues) == 1 {
					refValue = attribute.Values[idx]
				} else {
					refValue = cellValue
				}

				color, ok := utils.GetAttrCellColor(cellName, refValue)

				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			if idx == 0 {
				attrsTable.SetCell(row, 1, myCell)
			} else {
				if expandAttrs {
					if attrLimit == -1 || idx < attrLimit {
						attrsTable.SetCell(row, 0, tview.NewTableCell(""))
						attrsTable.SetCell(row, 1, myCell)
						if idx == attrLimit-1 {
							attrsTable.SetCell(row+1, 1, tview.NewTableCell("[entries hidden]"))
							row = row + 2
							break
						}
					}
				}
			}

			row = row + 1
		}
	}

	attrsTable.ScrollToBeginning()
	go func() {
		app.Draw()
	}()
	return nil
}

func getName(entry *ldap.Entry) string {
	nameIds := []string{"cn", "ou", "dc", "name"}
	objectName := ""
	for _, nameId := range nameIds {
		currentId := entry.GetAttributeValue(nameId)

		if currentId != "" {
			objectName = currentId
			break
		}
	}

	return objectName
}

func getDN(entry *ldap.Entry) string {
	dn := entry.DN

	if dn == "" {
		dnIds := []string{"distinguishedName", "dn"}
		for _, dnId := range dnIds {
			currentId := entry.GetAttributeValue(dnId)

			if currentId != "" {
				dn = currentId
				break
			}
		}
	}

	return dn
}

func getNodeName(entry *ldap.Entry) string {
	var classEmojisBuf bytes.Buffer
	var emojisPrefix string

	objectClasses := entry.GetAttributeValues("objectClass")
	isDomain := false
	for _, objectClass := range objectClasses {
		if objectClass == "domain" || objectClass == "dcObject" {
			isDomain = true
		}

		if emoji, ok := utils.EmojiMap[objectClass]; ok {
			classEmojisBuf.WriteString(emoji)
		}
	}

	emojisPrefix = classEmojisBuf.String()

	entryMarker := regexp.MustCompile("DEL:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")

	if len(emojisPrefix) == 0 {
		emojisPrefix = utils.EmojiMap["container"]
	}

	if emojis {
		return emojisPrefix + entryMarker.ReplaceAllString(getName(entry), "")
	}

	dn := getDN(entry)
	if isDomain {
		return dn
	}

	dnParts := strings.Split(dn, ",")
	if len(dnParts) > 0 {
		return dnParts[0]
	}

	return dn
}

func updateEmojis() {
	rootExplorer := treePanel.GetRoot()
	if rootExplorer != nil {
		rootExplorer.Walk(func(node *tview.TreeNode, parent *tview.TreeNode) bool {
			ref := node.GetReference()
			if ref != nil {
				entry, ok := explorerCache.Get(ref.(string))

				if ok {
					node.SetText(getNodeName(entry))
				}
			}

			return true
		})
	}

	rootSearch := searchTreePanel.GetRoot()
	if rootSearch != nil {
		rootSearch.Walk(func(node *tview.TreeNode, parent *tview.TreeNode) bool {
			ref := node.GetReference()
			if ref != nil {
				entry, ok := searchCache.Get(ref.(string))

				if ok {
					node.SetText(getNodeName(entry))
				}
			}

			return true
		})
	}
}

func renderPartialTree(rootDN string, searchFilter string) *tview.TreeNode {
	rootEntry, err := lc.Query(rootDN, "(objectClass=*)", ldap.ScopeBaseObject, deleted)
	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		return nil
	}

	if len(rootEntry) != 1 {
		updateLog("Root entry not found.", "red")
		return nil
	}

	explorerCache.Add(rootDN, rootEntry[0])

	rootNodeName := getNodeName(rootEntry[0])
	if rootDN == "" {
		rootNodeName += "RootDSE"
	}

	rootNode = tview.NewTreeNode(rootNodeName).
		SetReference(rootDN).
		SetSelectable(true)

	if rootDN == "" {
		return rootNode
	}

	var rootEntries []*ldap.Entry
	rootEntries, err = lc.Query(rootDN, searchFilter, ldap.ScopeSingleLevel, deleted)
	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		return nil
	}

	// Sort results to guarantee stable view
	sort.Slice(rootEntries, func(i int, j int) bool {
		return getName(rootEntries[i]) < getName(rootEntries[j])
	})

	for _, entry := range rootEntries {
		node := createTreeNodeFromEntry(entry)
		if node != nil {
			rootNode.AddChild(node)
		}
	}

	return rootNode
}

func reloadExplorerPage() {
	explorerAttrsPanel.Clear()
	explorerCache.Clear()

	rootNode = renderPartialTree(lc.RootDN, searchFilter)
	if rootNode != nil {
		numChildren := len(rootNode.GetChildren())
		updateLog("Tree updated successfully ("+strconv.Itoa(numChildren)+" objects found)", "green")
	}

	treePanel.SetRoot(rootNode).SetCurrentNode(rootNode)
}
