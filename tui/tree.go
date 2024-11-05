package tui

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var selectedAttrName string = "objectClass"

func storeAnchoredAttribute(attrsPanel *tview.Table) func(row, column int) {
	return func(row, column int) {
		selectedText := attrsPanel.GetCell(row, 0)
		cellRef := selectedText.GetReference()
		if cellRef != nil {
			attrName, ok := cellRef.(string)
			if ok {
				selectedAttrName = attrName
			}
		}
	}
}

func selectAnchoredAttribute(attrsPanel *tview.Table) {
	rowCount := attrsPanel.GetRowCount()

	for idx := 0; idx < rowCount; idx++ {
		cell := attrsPanel.GetCell(idx, 0)
		cellRef := cell.GetReference()
		if cellRef == nil {
			continue
		}

		cellAttrName, ok := cellRef.(string)
		if !ok {
			continue
		}

		if cellAttrName == selectedAttrName {
			attrsPanel.Select(idx, 0)
			break
		}
	}
}

func createTreeNodeFromEntry(entry *ldap.Entry) *tview.TreeNode {
	_, ok := explorerCache.Get(entry.DN)

	if !ok {
		nodeName := getNodeName(entry)

		node := tview.NewTreeNode(nodeName).
			SetReference(entry.DN).
			SetSelectable(true)

		// Helpful node coloring for deleted and disabled objects
		if Colors {
			color, changed := GetEntryColor(entry)
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
	entries, err := lc.Query(baseDN, SearchFilter, ldap.ScopeSingleLevel, Deleted)
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
	attrRow, attrCol := attrsPanel.GetSelection()

	// Find the correct attribute name and value index
	selectedIndex := 0
	parentRow := attrRow
	if attrCol == 1 && attrsPanel.GetCell(attrRow, 0).Text == "" {
		// Count back to find parent attribute row
		for parentRow >= 0 && attrsPanel.GetCell(parentRow, 0).Text == "" {
			parentRow--
		}
		// Calculate index by counting rows from parent
		selectedIndex = attrRow - parentRow
	}

	attrNameRef := attrsPanel.GetCell(parentRow, 0).GetReference().(string)

	baseDN := currentNode.GetReference().(string)

	entry, _ := cache.Get(baseDN)
	attrVals := entry.GetAttributeValues(attrNameRef)
	if len(attrVals) == 0 || selectedIndex < 0 || selectedIndex >= len(attrVals) {
		return
	}

	// Encode attribute values to hex
	rawAttrVals := entry.GetRawAttributeValues(attrNameRef)

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

	useHexEncoding := false

	writeAttrValsForm := NewXForm()
	writeAttrValsForm.
		AddTextView("Base DN", baseDN, 0, 1, false, true).
		AddTextView("Attribute Name", attrNameRef, 0, 1, false, true).
		AddTextView("Current Value", attrVals[selectedIndex], 0, 1, false, true).
		AddTextView("Current Value (HEX)", attrValsHex[selectedIndex], 0, 1, false, true).
		AddDropDown("Value Index", valIndices, selectedIndex, func(option string, optionIndex int) {
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

			err := lc.ModifyAttribute(baseDN, attrNameRef, attrVals)
			// TODO: Don't go back immediately so that the user can
			// change multiple values at once
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
			} else {
				updateLog("Attribute updated: '"+attrNameRef+"' from '"+baseDN+"'", "green")
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

	//assignFormTheme(writeAttrValsForm)

	writeAttrValsForm.SetInputCapture(handleEscape(treePanel))
	writeAttrValsForm.SetTitle("Attribute Editor").SetBorder(true)
	app.SetRoot(writeAttrValsForm, true).SetFocus(writeAttrValsForm)
}
func handleAttrsKeyDelete(currentNode *tview.TreeNode, attrsPanel *tview.Table, cache *EntryCache) {
	currentFocus := app.GetFocus()
	baseDN := currentNode.GetReference().(string)

	attrRow, attrCol := attrsPanel.GetSelection()
	attrName := attrsPanel.GetCell(attrRow, 0).Text
	attrNameRef := attrsPanel.GetCell(attrRow, 0).GetReference().(string)
	attrValue := attrsPanel.GetCell(attrRow, 1).Text

	promptModal := tview.NewModal()
	if attrCol == 0 && attrName != "" {
		// Deleting entire attribute
		promptModal.
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
	} else {
		// Deleting specific attribute value
		promptModal.
			SetText("Do you really want to delete this value from this attribute?\nValue: " + attrValue + "\nAttribute: " + attrNameRef + "\nObject: " + baseDN).
			AddButtons([]string{"No", "Yes"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				if buttonLabel == "Yes" {
					err := lc.DeleteAttributeValues(baseDN, attrNameRef, []string{attrValue})
					if err != nil {
						updateLog(fmt.Sprint(err), "red")
					} else {
						cache.Delete(baseDN)
						reloadAttributesPanel(currentNode, attrsPanel, false, cache)
						updateLog("Value deleted: "+attrValue+" from attribute "+attrNameRef, "green")
					}
				}
				app.SetRoot(appPanel, true).SetFocus(currentFocus)
			})
	}

	app.SetRoot(promptModal, false).SetFocus(promptModal)
}

func handleAttrsKeyCtrlN(currentNode *tview.TreeNode, attrsPanel *tview.Table, cache *EntryCache) {
	currentFocus := app.GetFocus()
	createAttrForm := NewXForm()
	//assignFormTheme(createAttrForm)
	createAttrForm.SetInputCapture(handleEscape(treePanel))

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

func handleAttrsKeyEnter(currentNode *tview.TreeNode, attrsPanel *tview.Table, cache *EntryCache) {
	selectedRow, selectedCol := attrsPanel.GetSelection()
	selectedCell := attrsPanel.GetCell(selectedRow, selectedCol)
	selectedCellRef := selectedCell.GetReference().(string)
	if selectedCellRef == "[HIDDEN]" {
		// Get the attribute name from the reference of the first cell in this row
		attrName := attrsPanel.GetCell(selectedRow, 0).GetReference().(string)

		// Get the current node's entry from the cache
		baseDN := currentNode.GetReference().(string)
		entry, _ := cache.Get(baseDN)

		// Get all values for this attribute
		attribute := entry.GetAttributeValues(attrName)

		// Remove the "[entries hidden]" row
		attrsPanel.RemoveRow(selectedRow)

		// Add all remaining values starting from AttrLimit
		currentRow := selectedRow
		for i := AttrLimit; i < len(attribute); i++ {
			attrsPanel.InsertRow(currentRow)
			attrsPanel.SetCell(currentRow, 0, tview.NewTableCell("").SetReference(attrName))

			cellValue := attribute[i]
			myCell := tview.NewTableCell(cellValue).SetReference(attrName)

			if Colors {
				color, ok := GetAttrCellColor(attrName, cellValue)
				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			attrsPanel.SetCell(currentRow, 1, myCell)
			currentRow++
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

func handleAttrsKeyLeft(attrsPanel *tview.Table) {
	selectedRow, selectedCol := attrsPanel.GetSelection()
	if selectedCol == 1 {
		s := selectedRow
		for s > 0 && attrsPanel.GetCell(s, 0).Text == "" {
			s = s - 1
		}

		if s != selectedRow {
			attrsPanel.Select(s, 0)
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
	case tcell.KeyEnter:
		handleAttrsKeyEnter(currentNode, attrsPanel, cache)
	case tcell.KeyLeft:
		handleAttrsKeyLeft(attrsPanel)
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
		entries, err := lc.Query(baseDN, SearchFilter, ldap.ScopeBaseObject, Deleted)
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

		attrsTable.SetCell(row, 0, tview.NewTableCell(cellName).SetReference(cellName))

		if FormatAttrs {
			cellValues = ldaputils.FormatLDAPAttribute(attribute, TimeFormat)
		} else {
			cellValues = attribute.Values
		}

		if !ExpandAttrs {
			myCell := tview.NewTableCell(strings.Join(cellValues, "; ")).SetReference(cellName)

			if Colors {
				color, ok := GetAttrCellColor(cellName, attribute.Values[0])
				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			attrsTable.SetCell(row, 1, myCell)
			row = row + 1
			continue
		}

		for idx, cellValue := range cellValues {
			myCell := tview.NewTableCell(cellValue).SetReference(cellName)

			if Colors {
				var refValue string
				if !ExpandAttrs || len(cellValues) == 1 {
					refValue = attribute.Values[idx]
				} else {
					refValue = cellValue
				}

				color, ok := GetAttrCellColor(cellName, refValue)

				if ok {
					myCell.SetTextColor(tcell.GetColor(color))
				}
			}

			if idx == 0 {
				attrsTable.SetCell(row, 1, myCell)
			} else {
				if ExpandAttrs {
					entriesHidden := len(cellValues) - AttrLimit
					if AttrLimit == -1 || idx < AttrLimit {
						attrsTable.SetCell(row, 0, tview.NewTableCell("").SetReference(cellName))
						attrsTable.SetCell(row, 1, myCell)
						if entriesHidden > 0 && idx == AttrLimit-1 {
							attrsTable.SetCell(row+1, 0, tview.NewTableCell("").SetReference(cellName))
							attrsTable.SetCell(row+1, 1,
								tview.NewTableCell(
									fmt.Sprintf("[%d entries hidden]", entriesHidden),
								).SetReference("[HIDDEN]"),
							)
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

		if emoji, ok := ldaputils.EmojiMap[objectClass]; ok {
			classEmojisBuf.WriteString(emoji)
		}
	}

	emojisPrefix = classEmojisBuf.String()

	entryMarker := regexp.MustCompile("DEL:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")

	if len(emojisPrefix) == 0 {
		emojisPrefix = ldaputils.EmojiMap["container"]
	}

	if Emojis {
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
	rootEntry, err := lc.Query(rootDN, "(objectClass=*)", ldap.ScopeBaseObject, Deleted)
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
	rootEntries, err = lc.Query(rootDN, searchFilter, ldap.ScopeSingleLevel, Deleted)
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

	rootNode = renderPartialTree(lc.RootDN, SearchFilter)
	if rootNode != nil {
		numChildren := len(rootNode.GetChildren())
		updateLog("Tree updated successfully ("+strconv.Itoa(numChildren)+" objects found)", "green")
	}

	treePanel.SetRoot(rootNode).SetCurrentNode(rootNode)
}
