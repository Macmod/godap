package main

import (
	"fmt"
	"github.com/Macmod/godap/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"strconv"
)

var explorerPage *tview.Flex
var treePanel *tview.TreeView
var attrsPanel *tview.Table
var rootDNInput *tview.InputField
var searchFilterInput *tview.InputField

func InitExplorerPage() {
	treePanel = tview.NewTreeView()

	rootNode = renderPartialTree(conn, rootDN, searchFilter)
	treePanel.SetRoot(rootNode).SetCurrentNode(rootNode)

	attrsPanel = tview.NewTable()
	attrsPanel.SetSelectable(true, true)

	searchFilterInput = tview.NewInputField().
		SetText(searchFilter)
	searchFilterInput.SetFieldBackgroundColor(tcell.GetColor("black"))
	searchFilterInput.SetTitle("Search Filter (Single-Level)")
	searchFilterInput.SetBorder(true)

	rootDNInput = tview.NewInputField().
		SetText(rootDN)
	rootDNInput.SetFieldBackgroundColor(tcell.GetColor("black"))
	rootDNInput.SetTitle("Root DN")
	rootDNInput.SetBorder(true)

	attrsPanel.SetBorder(true)
	attrsPanel.SetTitle("Attributes")

	// Event Handlers
	searchFilterInput.SetDoneFunc(func(key tcell.Key) {
		searchFilter = searchFilterInput.GetText()
		reloadPage()
	})

	rootDNInput.SetDoneFunc(func(key tcell.Key) {
		rootDN = rootDNInput.GetText()
		reloadPage()
	})

	treeFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(searchFilterInput, 0, 1, false).
				AddItem(rootDNInput, 0, 1, false),
			0, 1, false,
		).
		AddItem(treePanel, 0, 8, false)

	treeFlex.SetBorder(true)
	treeFlex.SetTitle("Tree View")
	explorerPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(treeFlex, 0, 1, false).
				AddItem(attrsPanel, 0, 1, false), 0, 8, false,
		)

	explorerPage.SetInputCapture(explorerPageKeyHandler)

	attrsPanel.SetInputCapture(attrsPanelKeyHandler)

	treePanel.SetInputCapture(treePanelKeyHandler)

	treePanel.SetChangedFunc(treePanelChangeHandler)
}

func treePanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	currentNode := treePanel.GetCurrentNode()
	if currentNode == nil {
		return event
	}

	switch event.Key() {
	case tcell.KeyRight:
		loadChildren(currentNode)
		currentNode.SetExpanded(true)
	case tcell.KeyLeft:
		currentNode.SetExpanded(false)
		if !cacheEntries {
			unloadChildren(currentNode)
		}
	case tcell.KeyDelete:
		baseDN := currentNode.GetReference().(string)
		promptModal := tview.NewModal().
			SetText("Do you really want to delete this object?\n" + baseDN).
			AddButtons([]string{"Yes", "No"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				if buttonLabel == "Yes" {
					err := utils.LDAPDeleteObject(conn, baseDN)
					if err == nil {
						delete(loadedDNs, baseDN)
						updateLog("Object deleted: "+baseDN, "green")

						pathToCurrent := treePanel.GetPath(currentNode)
						parent := pathToCurrent[len(pathToCurrent)-2]
						siblings := parent.GetChildren()

						var otherNodeToSelect *tview.TreeNode = parent
						for idx, node := range siblings {
							if node == currentNode && idx > 0 {
								otherNodeToSelect = siblings[idx-1]
							}
						}

						parent.RemoveChild(currentNode)
						treePanel.SetCurrentNode(otherNodeToSelect)
					}
				}

				app.SetRoot(appPanel, true).SetFocus(treePanel)
			})

		app.SetRoot(promptModal, false).SetFocus(promptModal)
	}

	return event
}

func treePanelChangeHandler(node *tview.TreeNode) {
	reloadAttributesPanel(node, cacheEntries)
}

func attrsPanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyDelete:
		currentNode := treePanel.GetCurrentNode()
		attrRow, _ := attrsPanel.GetSelection()

		baseDN := currentNode.GetReference().(string)
		attrName := attrsPanel.GetCell(attrRow, 0).Text

		promptModal := tview.NewModal().
			SetText("Do you really want to delete attribute `" + attrName + "` of this object?\n" + baseDN).
			AddButtons([]string{"Yes", "No"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				if buttonLabel == "Yes" {
					err := utils.LDAPDeleteAttribute(conn, baseDN, attrName)
					if err == nil {
						delete(loadedDNs, baseDN)
						updateLog("Attribute deleted: "+attrName+" from "+baseDN, "green")

						err = reloadAttributesPanel(currentNode, cacheEntries)
						if err != nil {
							updateLog(fmt.Sprint(err), "red")
						}
					}
				}

				app.SetRoot(appPanel, true).SetFocus(treePanel)
			})

		app.SetRoot(promptModal, false).SetFocus(promptModal)
	case tcell.KeyCtrlN:
		currentNode := treePanel.GetCurrentNode()
		if currentNode == nil {
			return event
		}

		createAttrForm := tview.NewForm()

		baseDN := currentNode.GetReference().(string)

		createAttrForm.
			AddTextView("Object DN", baseDN, 0, 1, false, true).
			AddInputField("Attribute Name", "", 20, nil, nil).
			AddInputField("Attribute Value", "", 20, nil, nil).
			SetFieldBackgroundColor(tcell.GetColor("black")).
			AddButton("Create", func() {
				attrName := createAttrForm.GetFormItemByLabel("Attribute Name").(*tview.InputField).GetText()
				attrVal := createAttrForm.GetFormItemByLabel("Attribute Value").(*tview.InputField).GetText()

				err := utils.LDAPAddAttribute(conn, baseDN, attrName, []string{attrVal})
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				} else {
					delete(loadedDNs, baseDN)
					updateLog("Attribute added: "+attrName+" to "+baseDN, "green")

					err = reloadAttributesPanel(currentNode, cacheEntries)
					if err != nil {
						updateLog(fmt.Sprint(err), "red")
					}
				}

				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			SetTitle("Attribute Creator").
			SetBorder(true)

		app.SetRoot(createAttrForm, true).SetFocus(createAttrForm)
	}

	return event
}

func explorerRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case treePanel:
		app.SetFocus(attrsPanel)
	case attrsPanel:
		app.SetFocus(treePanel)
	}
}

func explorerPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		explorerRotateFocus()
		return nil
	}

	switch event.Key() {
	case tcell.KeyCtrlE:
		currentNode := treePanel.GetCurrentNode()
		if currentNode == nil {
			return event
		}

		writeAttrValsForm := tview.NewForm()

		attrRow, _ := attrsPanel.GetSelection()
		baseDN := currentNode.GetReference().(string)
		attrName := attrsPanel.GetCell(attrRow, 0).Text

		entry := loadedDNs[baseDN]
		attrVals := entry.GetAttributeValues(attrName)
		if len(attrVals) == 0 {
			return event
		}

		valIndices := []string{}

		for idx := range attrVals {
			valIndices = append(valIndices, strconv.Itoa(idx))
		}

		selectedIndex := 0

		writeAttrValsForm = writeAttrValsForm.
			AddTextView("Base DN", baseDN, 0, 1, false, true).
			AddTextView("Attribute Name", attrName, 0, 1, false, true).
			AddTextView("Current Value", attrVals[0], 0, 1, false, true).
			AddDropDown("Value Index", valIndices, 0, func(option string, optionIndex int) {
				selectedIndex = optionIndex
				currentValItem := writeAttrValsForm.GetFormItemByLabel("Current Value").(*tview.TextView)
				if currentValItem != nil {
					currentValItem.SetText(attrVals[selectedIndex])
				}
			}).
			AddInputField("New Value", "", 0, nil, nil).
			SetFieldBackgroundColor(tcell.GetColor("black")).
			AddButton("Update", func() {
				attrVals[selectedIndex] = writeAttrValsForm.GetFormItemByLabel("New Value").(*tview.InputField).GetText()

				err := utils.LDAPModifyAttribute(conn, baseDN, attrName, attrVals)
				// TODO: Don't go back immediately so that the user can
				// change multiple values at once
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				}
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			})

		writeAttrValsForm.SetTitle("Attribute Editor").SetBorder(true)
		app.SetRoot(writeAttrValsForm, true).SetFocus(writeAttrValsForm)
	case tcell.KeyCtrlP:
		currentNode := treePanel.GetCurrentNode()
		if currentNode == nil {
			return event
		}

		changePasswordForm := tview.NewForm()

		baseDN := currentNode.GetReference().(string)
		changePasswordForm = changePasswordForm.
			AddTextView("Object DN", baseDN, 0, 1, false, true).
			AddPasswordField("New Password", "", 20, '*', nil).
			SetFieldBackgroundColor(tcell.GetColor("black")).
			AddButton("Update", func() {
				newPassword := changePasswordForm.GetFormItemByLabel("New Password").(*tview.InputField).GetText()

				err := utils.LDAPResetPassword(conn, baseDN, newPassword)
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				} else {
					updateLog("Password changed: "+baseDN, "green")
				}

				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			})

		changePasswordForm.SetTitle("Password Editor").SetBorder(true)
		app.SetRoot(changePasswordForm, true).SetFocus(changePasswordForm)
	}

	return event
}
