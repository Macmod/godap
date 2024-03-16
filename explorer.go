package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strconv"
	"time"

	"github.com/Macmod/godap/v2/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var (
	explorerCache      EntryCache
	explorerPage       *tview.Flex
	treePanel          *tview.TreeView
	explorerAttrsPanel *tview.Table
	rootDNInput        *tview.InputField
	searchFilterInput  *tview.InputField
	treeFlex           *tview.Flex
)

func initExplorerPage() {
	explorerCache = EntryCache{
		entries: make(map[string]*ldap.Entry),
	}

	treePanel = tview.NewTreeView()

	rootNode = renderPartialTree(rootDN, searchFilter)
	treePanel.SetRoot(rootNode).SetCurrentNode(rootNode)

	explorerAttrsPanel = tview.NewTable().SetSelectable(true, true)

	searchFilterInput = tview.NewInputField().
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetText(searchFilter)
	searchFilterInput.SetTitle("Expand Filter")
	searchFilterInput.SetBorder(true)

	rootDNInput = tview.NewInputField().
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetText(rootDN)
	rootDNInput.SetTitle("Root DN")
	rootDNInput.SetBorder(true)

	explorerAttrsPanel.
		SetEvaluateAllRows(true).
		SetTitle("Attributes").
		SetBorder(true)

	// Event Handlers
	searchFilterInput.SetDoneFunc(func(key tcell.Key) {
		searchFilter = searchFilterInput.GetText()
		reloadExplorerPage()
	})

	rootDNInput.SetDoneFunc(func(key tcell.Key) {
		lc.RootDN = rootDNInput.GetText()
		reloadExplorerPage()
	})

	treeFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(searchFilterInput, 0, 1, false).
				AddItem(rootDNInput, 0, 1, false),
			3, 0, false,
		).
		AddItem(treePanel, 0, 1, false)

	treeFlex.SetBorder(true)
	treeFlex.SetTitle("Tree View")
	explorerPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(treeFlex, 0, 1, false).
				AddItem(explorerAttrsPanel, 0, 1, false), 0, 1, false,
		)

	explorerPage.SetInputCapture(explorerPageKeyHandler)

	explorerAttrsPanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		currentNode := treePanel.GetCurrentNode()
		if currentNode == nil || currentNode.GetReference() == nil {
			return event
		}

		return attrsPanelKeyHandler(event, currentNode, &explorerCache, explorerAttrsPanel)
	})

	treePanel.SetInputCapture(treePanelKeyHandler)

	treePanel.SetChangedFunc(treePanelChangeHandler)
}

func expandTreeNode(node *tview.TreeNode) {
	if !node.IsExpanded() {
		if len(node.GetChildren()) == 0 {
			go func() {
				updateLog("Loading children ("+node.GetReference().(string)+")", "yellow")
				loadChildren(node)

				n := len(node.GetChildren())

				if n != 0 {
					node.SetExpanded(true)
					updateLog("Loaded "+strconv.Itoa(n)+" children ("+node.GetReference().(string)+")", "green")
				} else {
					updateLog("Node "+node.GetReference().(string)+" has no children", "green")
				}
				app.Draw()
			}()
		} else {
			node.SetExpanded(true)
		}
	}
}

func collapseTreeNode(node *tview.TreeNode) {
	node.SetExpanded(false)
	if !cacheEntries {
		unloadChildren(node)
	}
}

func reloadParentNode(node *tview.TreeNode) *tview.TreeNode {
	parent := getParentNode(node)

	if parent != nil {
		unloadChildren(parent)
		loadChildren(parent)
	}

	go func() {
		app.Draw()
	}()

	return parent
}

func reloadExplorerAttrsPanel(node *tview.TreeNode, useCache bool) {
	reloadAttributesPanel(node, explorerAttrsPanel, useCache, &explorerCache)
}

func getParentNode(node *tview.TreeNode) *tview.TreeNode {
	pathToCurrent := treePanel.GetPath(node)

	if len(pathToCurrent) > 1 {
		return pathToCurrent[len(pathToCurrent)-2]
	}

	return nil
}

func findEntryInChildren(dn string, parent *tview.TreeNode) int {
	siblings := parent.GetChildren()

	for idx, loopNode := range siblings {
		if loopNode.GetReference().(string) == dn {
			return idx
		}
	}

	return -1
}

func handleEscapeToTree(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyEscape {
		app.SetRoot(appPanel, true).SetFocus(treePanel)
		return nil
	}
	return event
}

func treePanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	currentNode := treePanel.GetCurrentNode()
	if currentNode == nil {
		return event
	}

	parentNode := getParentNode(currentNode)
	baseDN := currentNode.GetReference().(string)

	switch event.Rune() {
	case 'r', 'R':
		go func() {
			updateLog("Reloading node "+baseDN, "yellow")

			explorerCache.Delete(baseDN)
			reloadAttributesPanel(currentNode, explorerAttrsPanel, false, &explorerCache)

			unloadChildren(currentNode)
			loadChildren(currentNode)

			updateLog("Node "+baseDN+" reloaded", "green")

			app.Draw()
		}()

		return event
	}

	switch event.Key() {
	case tcell.KeyRight:
		expandTreeNode(currentNode)
		return nil
	case tcell.KeyLeft:
		if currentNode.IsExpanded() { // Collapse current node
			collapseTreeNode(currentNode)
			treePanel.SetCurrentNode(currentNode)
			return nil
		} else { // Collapse parent node
			pathToCurrent := treePanel.GetPath(currentNode)
			if len(pathToCurrent) > 1 {
				parentNode := pathToCurrent[len(pathToCurrent)-2]
				collapseTreeNode(parentNode)
				treePanel.SetCurrentNode(parentNode)
			}
			return nil
		}
	case tcell.KeyDelete:
		baseDN := currentNode.GetReference().(string)
		promptModal := tview.NewModal().
			SetText("Do you really want to delete this object?\n" + baseDN).
			AddButtons([]string{"No", "Yes"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				if buttonLabel == "Yes" {
					err := lc.DeleteObject(baseDN)
					if err == nil {
						explorerCache.Delete(baseDN)

						if parentNode != nil {
							idx := findEntryInChildren(baseDN, parentNode)

							parent := reloadParentNode(currentNode)
							otherNodeToSelect := parent

							if idx > 0 {
								siblings := parent.GetChildren()
								otherNodeToSelect = siblings[idx-1]
							}

							treePanel.SetCurrentNode(otherNodeToSelect)
						} else {
							reloadExplorerPage()
						}

						updateLog("Object deleted: "+baseDN, "green")
					}
				}

				app.SetRoot(appPanel, true).SetFocus(treePanel)
			})

		app.SetRoot(promptModal, false).SetFocus(promptModal)
	case tcell.KeyCtrlN:
		createObjectForm := NewXForm().
			AddDropDown("Object Type", []string{"OrganizationalUnit", "Container", "User", "Group", "Computer"}, 0, nil).
			AddInputField("Object Name", "", 0, nil, nil).
			AddInputField("Parent DN", baseDN, 0, nil, nil)
		createObjectForm.
			SetButtonBackgroundColor(formButtonBackgroundColor).
			SetButtonTextColor(formButtonTextColor).
			SetButtonActivatedStyle(formButtonActivatedStyle).
			SetInputCapture(handleEscapeToTree)

		createObjectForm.
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, true).SetFocus(treePanel)
			}).
			AddButton("Create", func() {
				// Note: It should be possible to walk upwards in the tree
				//   to find the first place where it's possible to place the object
				//   but it makes sense that the user should
				//   have full control over this behavior
				//   rather than automatically detecting
				//   an appropriate DN

				// pathToCurrent := treePanel.GetPath(currentNode)
				// lastNode := len(pathToCurrent) - 1
				// for nodeInPathIdx := range pathToCurrent {
				//   currentNodeIdx := lastNode - nodeInPathIdx
				// }

				_, objectType := createObjectForm.GetFormItemByLabel("Object Type").(*tview.DropDown).GetCurrentOption()

				objectName := createObjectForm.GetFormItemByLabel("Object Name").(*tview.InputField).GetText()

				var err error = nil

				switch objectType {
				case "OrganizationalUnit":
					err = lc.AddOrganizationalUnit(objectName, baseDN)
				case "Container":
					err = lc.AddContainer(objectName, baseDN)
				case "User":
					err = lc.AddUser(objectName, baseDN)
				case "Group":
					err = lc.AddGroup(objectName, baseDN)
				case "Computer":
					err = lc.AddComputer(objectName, baseDN)
				}

				if err != nil {
					updateLog(fmt.Sprintf("%s", err), "red")
				} else {
					updateLog("Object created successfully at: "+baseDN, "green")
				}

				reloadExplorerAttrsPanel(currentNode, cacheEntries)

				// Not the best approach but for now it works :)
				collapseTreeNode(currentNode)
				expandTreeNode(currentNode)
				treePanel.SetCurrentNode(currentNode)

				app.SetRoot(appPanel, true).SetFocus(treePanel)
			})

		createObjectForm.SetTitle("Object Creator").SetBorder(true)
		app.SetRoot(createObjectForm, true).SetFocus(createObjectForm)
	case tcell.KeyCtrlS:
		exportMap := make(map[string]*ldap.Entry)
		currentNode.Walk(func(node, parent *tview.TreeNode) bool {
			nodeDN := node.GetReference().(string)
			exportMap[nodeDN], _ = explorerCache.Get(nodeDN)
			return true
		})

		jsonExportMap, _ := json.MarshalIndent(exportMap, "", " ")

		unixTimestamp := time.Now().Unix()

		outputFilename := fmt.Sprintf("%d_objects.json", unixTimestamp)

		err := ioutil.WriteFile(outputFilename, jsonExportMap, 0644)

		if err != nil {
			updateLog(fmt.Sprintf("%s", err), "red")
		} else {
			updateLog("File '"+outputFilename+"' saved successfully!", "green")
		}
	case tcell.KeyCtrlA:
		baseDN := currentNode.GetReference().(string)

		updateUacForm := NewXForm()
		updateUacForm.
			SetButtonBackgroundColor(formButtonBackgroundColor).
			SetButtonTextColor(formButtonTextColor).
			SetButtonActivatedStyle(formButtonActivatedStyle)
		updateUacForm.SetInputCapture(handleEscapeToTree)
		updateUacForm.SetItemPadding(0)

		var checkboxState int = 0
		obj, _ := explorerCache.Get(baseDN)
		if obj != nil {
			uacValue, err := strconv.Atoi(obj.GetAttributeValue("userAccountControl"))
			if err == nil {
				checkboxState = uacValue
			} else {
				return nil
			}
		}

		updateUacForm.
			AddTextView("Raw UAC Value", strconv.Itoa(checkboxState), 0, 1, false, true)

		uacValues := make([]int, 0)
		for key, _ := range utils.UacFlags {
			uacValues = append(uacValues, key)
		}
		sort.Ints(uacValues)

		for _, val := range uacValues {
			uacValue := val
			updateUacForm.AddCheckbox(
				utils.UacFlags[uacValue].Present,
				checkboxState&uacValue != 0,
				func(checked bool) {
					if checked {
						checkboxState |= uacValue
					} else {
						checkboxState &^= uacValue
					}

					uacPreview := updateUacForm.GetFormItemByLabel("Raw UAC Value").(*tview.TextView)
					if uacPreview != nil {
						uacPreview.SetText(strconv.Itoa(checkboxState))
					}
				})
		}

		updateUacForm.
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, true).SetFocus(treePanel)
			}).
			AddButton("Update", func() {
				strCheckboxState := strconv.Itoa(checkboxState)
				err := lc.ModifyAttribute(baseDN, "userAccountControl", []string{strCheckboxState})

				if err != nil {
					updateLog(fmt.Sprintf("%s", err), "red")
				} else {
					if parentNode != nil {
						idx := findEntryInChildren(baseDN, parentNode)

						parent := reloadParentNode(currentNode)
						siblings := parent.GetChildren()

						reloadExplorerAttrsPanel(currentNode, false)

						treePanel.SetCurrentNode(siblings[idx])
					} else {
						reloadExplorerPage()
					}

					updateLog("Object's UAC updated to "+strCheckboxState+" at: "+baseDN, "green")
				}

				app.SetRoot(appPanel, true).SetFocus(treePanel)
			})

		updateUacForm.SetTitle("userAccountControl Editor").SetBorder(true)
		app.SetRoot(updateUacForm, true).SetFocus(updateUacForm)
	}

	return event
}

func treePanelChangeHandler(node *tview.TreeNode) {
	go func() {
		// TODO: Implement cancellation
		reloadExplorerAttrsPanel(node, cacheEntries)
	}()
}

func explorerRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case treePanel:
		app.SetFocus(explorerAttrsPanel)
	case explorerAttrsPanel:
		app.SetFocus(treePanel)
	}
}

func explorerPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		explorerRotateFocus()
		return nil
	}

	currentNode := treePanel.GetCurrentNode()
	if currentNode == nil {
		return event
	}

	switch event.Key() {
	case tcell.KeyCtrlP:
		changePasswordForm := NewXForm()

		baseDN := currentNode.GetReference().(string)
		changePasswordForm.
			AddTextView("Object DN", baseDN, 0, 1, false, true).
			AddPasswordField("New Password", "", 20, '*', nil).
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			AddButton("Update", func() {
				newPassword := changePasswordForm.GetFormItemByLabel("New Password").(*tview.InputField).GetText()

				err := lc.ResetPassword(baseDN, newPassword)
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				} else {
					updateLog("Password changed: "+baseDN, "green")
				}

				app.SetRoot(appPanel, false).SetFocus(treePanel)
			})

		changePasswordForm.SetTitle("Password Editor").SetBorder(true)
		changePasswordForm.
			SetButtonBackgroundColor(formButtonBackgroundColor).
			SetButtonTextColor(formButtonTextColor).
			SetButtonActivatedStyle(formButtonActivatedStyle)
		changePasswordForm.SetInputCapture(handleEscapeToTree)

		app.SetRoot(changePasswordForm, true).SetFocus(changePasswordForm)
	case tcell.KeyCtrlL:
		baseDN := currentNode.GetReference().(string)

		moveObjectForm := NewXForm()
		moveObjectForm.
			AddTextView("Object DN", baseDN, 0, 1, false, true).
			AddInputField("New Object DN", baseDN, 0, nil, nil).
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			AddButton("Update", func() {
				newObjectDN := moveObjectForm.GetFormItemByLabel("New Object DN").(*tview.InputField).GetText()

				err := lc.MoveObject(baseDN, newObjectDN)

				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				} else {
					updateLog("Object moved from '"+baseDN+"' to '"+newObjectDN+"'", "green")
				}

				newParentNode := reloadParentNode(currentNode)

				idx := findEntryInChildren(newObjectDN, newParentNode)

				otherNodeToSelect := newParentNode

				if idx > 0 {
					siblings := newParentNode.GetChildren()
					otherNodeToSelect = siblings[idx]
				}

				treePanel.SetCurrentNode(otherNodeToSelect)
				reloadExplorerAttrsPanel(otherNodeToSelect, cacheEntries)

				app.SetRoot(appPanel, false).SetFocus(treePanel)
			})

		moveObjectForm.SetTitle("Move Object").SetBorder(true)
		moveObjectForm.SetInputCapture(handleEscapeToTree)
		moveObjectForm.
			SetButtonBackgroundColor(formButtonBackgroundColor).
			SetButtonTextColor(formButtonTextColor).
			SetButtonActivatedStyle(formButtonActivatedStyle)
		app.SetRoot(moveObjectForm, true).SetFocus(moveObjectForm)
	}

	return event
}
