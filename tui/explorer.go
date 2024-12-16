package tui

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
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

	addMemberToGroupFormValidation bool
)

func initExplorerPage() {
	explorerCache = EntryCache{
		entries: make(map[string]*ldap.Entry),
	}

	treePanel = tview.NewTreeView()

	rootNode = renderPartialTree(RootDN, SearchFilter)
	treePanel.SetRoot(rootNode).SetCurrentNode(rootNode)

	explorerAttrsPanel = tview.NewTable().SetSelectable(true, true)

	searchFilterInput = tview.NewInputField().
		SetText(SearchFilter)
	searchFilterInput.SetTitle("Expand Filter")
	searchFilterInput.SetBorder(true)
	assignInputFieldTheme(searchFilterInput)

	rootDNInput = tview.NewInputField().
		SetText(RootDN)
	rootDNInput.SetTitle("Root DN")
	rootDNInput.SetBorder(true)
	assignInputFieldTheme(rootDNInput)

	explorerAttrsPanel.
		SetEvaluateAllRows(true).
		SetTitle("Attributes").
		SetBorder(true)

	// Event Handlers
	searchFilterInput.SetDoneFunc(func(key tcell.Key) {
		SearchFilter = searchFilterInput.GetText()
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

	explorerAttrsPanel.SetSelectionChangedFunc(storeAnchoredAttribute(explorerAttrsPanel))

	treePanel.SetInputCapture(treePanelKeyHandler)

	treePanel.SetChangedFunc(treePanelChangeHandler)
}

func expandTreeNode(node *tview.TreeNode) {
	if !node.IsExpanded() {
		if len(node.GetChildren()) == 0 {
			go app.QueueUpdateDraw(func() {
				updateLog("Loading children ("+node.GetReference().(string)+")", "yellow")
				loadChildren(node)

				n := len(node.GetChildren())

				if n != 0 {
					node.SetExpanded(true)
					updateLog("Loaded "+strconv.Itoa(n)+" children ("+node.GetReference().(string)+")", "green")
				} else {
					updateLog("Node "+node.GetReference().(string)+" has no children", "green")
				}
			})
		} else {
			node.SetExpanded(true)
		}
	}
}

func collapseTreeNode(node *tview.TreeNode) {
	node.SetExpanded(false)
	if !CacheEntries {
		unloadChildren(node)
	}
}

func reloadParentNode(node *tview.TreeNode) *tview.TreeNode {
	parent := getParentNode(node, treePanel)

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

func exportCacheToFile(currentNode *tview.TreeNode, cache *EntryCache, outputFilename string) {
	exportMap := make(map[string]*ldap.Entry)
	currentNode.Walk(func(node, parent *tview.TreeNode) bool {
		if node.GetReference() != nil {
			nodeDN := node.GetReference().(string)
			exportMap[nodeDN], _ = cache.Get(nodeDN)
		}
		return true
	})

	jsonExportMap, _ := json.MarshalIndent(exportMap, "", " ")

	err := ioutil.WriteFile(outputFilename, jsonExportMap, 0644)

	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	} else {
		updateLog("File '"+outputFilename+"' saved successfully!", "green")
	}
}

func openDeleteObjectForm(node *tview.TreeNode, done func()) {
	currentFocus := app.GetFocus()
	baseDN := node.GetReference().(string)
	promptModal := tview.NewModal().
		SetText("Do you really want to delete this object?\n" + baseDN).
		AddButtons([]string{"No", "Yes"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				err := lc.DeleteObject(baseDN)
				if err != nil {
					updateLog(fmt.Sprintf("%s", err), "red")
				} else {
					if done != nil {
						done()
					}

					updateLog("Object deleted: "+baseDN, "green")
				}
			}

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		})

	app.SetRoot(promptModal, false).SetFocus(promptModal)
}

func openUpdateUacForm(node *tview.TreeNode, cache *EntryCache, done func()) {
	currentFocus := app.GetFocus()
	baseDN := node.GetReference().(string)

	updateUacForm := NewXForm()
	//assignFormTheme(updateUacForm)
	updateUacForm.SetInputCapture(handleEscape(treePanel))
	updateUacForm.SetItemPadding(0)

	var checkboxState int = 0
	obj, _ := cache.Get(baseDN)
	if obj != nil {
		uacValue, err := strconv.Atoi(obj.GetAttributeValue("userAccountControl"))
		if err == nil {
			checkboxState = uacValue
		} else {
			return
		}
	}

	updateUacForm.
		AddTextView("Raw UAC Value", strconv.Itoa(checkboxState), 0, 1, false, true)

	uacValues := make([]int, 0)
	for key := range ldaputils.UacFlags {
		uacValues = append(uacValues, key)
	}
	sort.Ints(uacValues)

	for _, val := range uacValues {
		uacValue := val
		updateUacForm.AddCheckbox(
			ldaputils.UacFlags[uacValue].Present,
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
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		}).
		AddButton("Update", func() {
			strCheckboxState := strconv.Itoa(checkboxState)
			err := lc.ModifyAttribute(baseDN, "userAccountControl", []string{strCheckboxState})

			if err != nil {
				updateLog(fmt.Sprintf("%s", err), "red")
			} else {
				if done != nil {
					done()
				}

				updateLog("Object's UAC updated to "+strCheckboxState+" at: "+baseDN, "green")
			}

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		})

	updateUacForm.SetTitle("userAccountControl Editor").SetBorder(true)
	app.SetRoot(updateUacForm, true).SetFocus(updateUacForm)
}

func openCreateObjectForm(node *tview.TreeNode, done func()) {
	currentFocus := app.GetFocus()
	baseDN := node.GetReference().(string)

	createObjectForm := NewXForm().
		AddDropDown("Object Type", []string{"OrganizationalUnit", "Container", "User", "Group", "Computer"}, 0, nil).
		AddInputField("Object Name", "", 0, nil, nil).
		AddInputField("Entry TTL", "-1", 0, nil, nil).
		AddInputField("Parent DN", baseDN, 0, nil, nil)
	createObjectForm.
		SetInputCapture(handleEscape(treePanel))

	createObjectForm.
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
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

			entryTTL := createObjectForm.GetFormItemByLabel("Entry TTL").(*tview.InputField).GetText()
			entryTTLInt, err := strconv.Atoi(entryTTL)
			if err != nil {
				entryTTLInt = -1
			}

			switch objectType {
			case "OrganizationalUnit":
				err = lc.AddOrganizationalUnit(objectName, baseDN, entryTTLInt)
			case "Container":
				err = lc.AddContainer(objectName, baseDN, entryTTLInt)
			case "User":
				err = lc.AddUser(objectName, baseDN, entryTTLInt)
			case "Group":
				err = lc.AddGroup(objectName, baseDN, entryTTLInt)
			case "Computer":
				err = lc.AddComputer(objectName, baseDN, entryTTLInt)
			default:
				err = fmt.Errorf("Invalid object type")
			}

			if err != nil {
				updateLog(fmt.Sprintf("%s", err), "red")
			} else {
				if done != nil {
					done()
				}
				updateLog("Object created successfully at: "+baseDN, "green")
			}

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		})

	createObjectForm.SetTitle("Object Creator").SetBorder(true)
	app.SetRoot(createObjectForm, true).SetFocus(createObjectForm)
}

func openAddMemberToGroupForm(targetDN string, isGroup bool) {
	currentFocus := app.GetFocus()

	addMemberForm := NewXForm().
		AddInputField("Group DN", "", 0, nil, nil).
		AddInputField("Object Name", "", 0, nil, nil).
		AddTextView("Object DN", "", 0, 1, false, true)

	objectNameFormItem := addMemberForm.GetFormItemByLabel("Object Name").(*tview.InputField)
	groupDNFormItem := addMemberForm.GetFormItemByLabel("Group DN").(*tview.InputField)

	groupDNFormItem.SetPlaceholder("Group DN")
	if isGroup {
		groupDNFormItem.SetText(targetDN)
	} else {
		objectNameFormItem.SetText(targetDN)
	}

	objectNameFormItem.SetPlaceholder("sAMAccountName or DN")
	assignInputFieldTheme(objectNameFormItem)
	assignInputFieldTheme(groupDNFormItem)

	objectDNFormItem := addMemberForm.GetFormItemByLabel("Object DN").(*tview.TextView)
	objectDNFormItem.SetDynamicColors(true)

	objectNameFormItem.SetDoneFunc(func(key tcell.Key) {
		object, err := lc.FindFirst(objectNameFormItem.GetText())
		if err == nil {
			addMemberToGroupFormValidation = true
			objectDNFormItem.SetText(object.DN)
		} else {
			addMemberToGroupFormValidation = false
			objectDNFormItem.SetText("[red]Object not found")
		}
	})

	//assignFormTheme(addMemberForm)

	addMemberForm.
		SetInputCapture(handleEscape(treePanel))

	addMemberForm.
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		}).
		AddButton("Add", func() {
			if !addMemberToGroupFormValidation {
				// TODO: Provide some feedback to the user?
				return
			}

			objectDN := addMemberForm.GetFormItemByLabel("Object DN").(*tview.TextView).GetText(true)

			err = lc.AddMemberToGroup(objectDN, targetDN)
			if err != nil {
				updateLog(fmt.Sprintf("%s", err), "red")
			} else {
				updateLog("Member '"+objectDN+"' added to group '"+targetDN+"'", "green")
			}

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		})

	addMemberForm.SetTitle("Add Group Member").SetBorder(true)
	app.SetRoot(addMemberForm, true).SetFocus(addMemberForm)
}

func treePanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	currentNode := treePanel.GetCurrentNode()
	if currentNode == nil {
		return event
	}

	parentNode := getParentNode(currentNode, treePanel)
	baseDN := currentNode.GetReference().(string)

	switch event.Rune() {
	case 'r', 'R':
		go app.QueueUpdateDraw(func() {
			updateLog("Reloading node "+baseDN, "yellow")

			explorerCache.Delete(baseDN)
			reloadAttributesPanel(currentNode, explorerAttrsPanel, false, &explorerCache)

			unloadChildren(currentNode)
			loadChildren(currentNode)

			updateLog("Node "+baseDN+" reloaded", "green")
		})

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
		openDeleteObjectForm(currentNode, func() {
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
		})
	case tcell.KeyCtrlN:
		openCreateObjectForm(currentNode, func() {
			reloadExplorerAttrsPanel(currentNode, CacheEntries)

			unloadChildren(currentNode)
			loadChildren(currentNode)
			treePanel.SetCurrentNode(currentNode)
		})
	case tcell.KeyCtrlS:
		unixTimestamp := time.Now().UnixMilli()
		outputFilename := fmt.Sprintf("%d_objects.json", unixTimestamp)
		exportCacheToFile(currentNode, &explorerCache, outputFilename)
	case tcell.KeyCtrlA:
		openUpdateUacForm(currentNode, &explorerCache, func() {
			if parentNode != nil {
				idx := findEntryInChildren(baseDN, parentNode)

				parent := reloadParentNode(currentNode)
				siblings := parent.GetChildren()

				reloadExplorerAttrsPanel(currentNode, false)

				treePanel.SetCurrentNode(siblings[idx])
			} else {
				reloadExplorerPage()
			}
		})
	case tcell.KeyCtrlG:
		entry := explorerCache.entries[baseDN]
		objClasses := entry.GetAttributeValues("objectClass")
		isGroup := slices.Contains(objClasses, "group")
		openAddMemberToGroupForm(baseDN, isGroup)
	case tcell.KeyCtrlD:
		info.Highlight("3")
		objectNameInputDacl.SetText(baseDN)
		queryDacl(baseDN)
	}

	return event
}

func treePanelChangeHandler(node *tview.TreeNode) {
	go app.QueueUpdateDraw(func() {
		// TODO: Implement cancellation
		reloadExplorerAttrsPanel(node, CacheEntries)
		selectAnchoredAttribute(explorerAttrsPanel)
	})
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

func openPasswordChangeForm(node *tview.TreeNode) {
	currentFocus := app.GetFocus()
	changePasswordForm := NewXForm()

	baseDN := node.GetReference().(string)
	changePasswordForm.
		AddTextView("Object DN", baseDN, 0, 1, false, true).
		AddPasswordField("New Password", "", 20, '*', nil).
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		}).
		AddButton("Update", func() {
			newPassword := changePasswordForm.GetFormItemByLabel("New Password").(*tview.InputField).GetText()

			err := lc.ResetPassword(baseDN, newPassword)
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
			} else {
				updateLog("Password changed: "+baseDN, "green")
			}

			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		})

	changePasswordForm.SetTitle("Password Editor").SetBorder(true)

	//assignFormTheme(changePasswordForm)

	changePasswordForm.SetInputCapture(handleEscape(treePanel))

	app.SetRoot(changePasswordForm, true).SetFocus(changePasswordForm)
}

func openMoveObjectForm(node *tview.TreeNode, done func(string)) {
	baseDN := node.GetReference().(string)
	currentFocus := app.GetFocus()

	moveObjectForm := NewXForm()
	moveObjectForm.
		AddTextView("Object DN", baseDN, 0, 1, false, true).
		AddInputField("New Object DN", baseDN, 0, nil, nil).
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		}).
		AddButton("Update", func() {
			newObjectDN := moveObjectForm.GetFormItemByLabel("New Object DN").(*tview.InputField).GetText()

			err := lc.MoveObject(baseDN, newObjectDN)

			if err != nil {
				updateLog(fmt.Sprint(err), "red")
			} else {
				updateLog("Object moved from '"+baseDN+"' to '"+newObjectDN+"'", "green")
				if done != nil {
					done(newObjectDN)
				}
			}

			app.SetRoot(appPanel, false).SetFocus(currentFocus)
		})

	moveObjectForm.SetTitle("Move Object").SetBorder(true)
	moveObjectForm.SetInputCapture(handleEscape(treePanel))
	//assignFormTheme(moveObjectForm)
	app.SetRoot(moveObjectForm, true).SetFocus(moveObjectForm)
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
	case tcell.KeyCtrlF:
		openFinder(&explorerCache, "LDAP Explorer")
	case tcell.KeyCtrlP:
		openPasswordChangeForm(currentNode)
	case tcell.KeyCtrlL:
		openMoveObjectForm(currentNode, func(newObjectDN string) {
			newParentNode := reloadParentNode(currentNode)

			idx := findEntryInChildren(newObjectDN, newParentNode)

			otherNodeToSelect := newParentNode

			if idx > 0 {
				siblings := newParentNode.GetChildren()
				otherNodeToSelect = siblings[idx]
			}

			treePanel.SetCurrentNode(otherNodeToSelect)
			reloadExplorerAttrsPanel(otherNodeToSelect, CacheEntries)
		})
	}

	return event
}
