package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Macmod/godap/v2/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var groupPage *tview.Flex
var groupNameInput *tview.InputField
var groupMembersPanel *tview.Table
var userNameInput *tview.InputField
var userGroupsPanel *tview.Table

func initGroupPage() {
	groupNameInput = tview.NewInputField()
	groupNameInput.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("Group (name or DN)").
		SetBorder(true)

	userNameInput = tview.NewInputField()
	userNameInput.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("User (sAMAccountName or DN)").
		SetBorder(true)

	groupMembersPanel = tview.NewTable()
	groupMembersPanel.
		SetSelectable(true, false).
		SetTitle("Group Members").
		SetBorder(true)

	groupMembersPanel.SetSelectedFunc(func(row, col int) {
		cell := groupMembersPanel.GetCell(row, col)
		cellId, ok := cell.GetReference().(string)
		if ok {
			userNameInput.SetText(cellId)
			app.SetFocus(userNameInput)
		}
	})

	userGroupsPanel = tview.NewTable()
	userGroupsPanel.
		SetSelectable(true, false).
		SetTitle("User Groups").
		SetBorder(true)
	userGroupsPanel.SetSelectedFunc(func(row, col int) {
		cell := userGroupsPanel.GetCell(row, col)
		cellId, ok := cell.GetReference().(string)
		if ok {
			groupNameInput.SetText(cellId)
			app.SetFocus(groupNameInput)
		}
	})

	groupPage = tview.NewFlex().
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(groupNameInput, 3, 0, false).
				AddItem(groupMembersPanel, 0, 8, false),
			0, 1, false,
		).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(userNameInput, 3, 0, false).
				AddItem(userGroupsPanel, 0, 8, false),
			0, 1, false,
		)

	groupPage.SetInputCapture(groupPageKeyHandler)
	groupNameInput.SetDoneFunc(func(key tcell.Key) {
		groupMembersPanel.Clear()

		entries, err := lc.QueryGroupMembers(groupNameInput.GetText())
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		for idx, entry := range entries {
			sAMAccountName := entry.GetAttributeValue("sAMAccountName")
			categoryDN := strings.Split(entry.GetAttributeValue("objectCategory"), ",")
			var category string
			if len(categoryDN) > 0 {
				category = categoryDN[0]
				if emojis {
					switch category {
					case "CN=Person":
						category = utils.EmojiMap["person"]
					case "CN=Group":
						category = utils.EmojiMap["group"]
					case "CN=Computer":
						category = utils.EmojiMap["computer"]
					}
				}
			} else {
				category = "Unknown"
			}

			groupMembersPanel.SetCell(idx, 0, tview.NewTableCell(sAMAccountName).SetReference(entry.DN))
			groupMembersPanel.SetCell(idx, 1, tview.NewTableCell(category).SetReference(entry.DN))
			groupMembersPanel.SetCell(idx, 2, tview.NewTableCell(entry.DN).SetReference(entry.DN))
		}

		groupMembersPanel.Select(0, 0)
		groupMembersPanel.ScrollToBeginning()
		app.SetFocus(groupMembersPanel)
		updateLog("Members query completed ("+strconv.Itoa(len(entries))+" objects found)", "green")
	})

	userNameInput.SetDoneFunc(func(key tcell.Key) {
		userGroupsPanel.Clear()

		entries, err := lc.QueryUserGroups(userNameInput.GetText())
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		var memberOf []string
		if len(entries) > 0 {
			memberOf = entries[0].GetAttributeValues("memberOf")

			for idx, group := range memberOf {
				userGroupsPanel.SetCell(idx, 0, tview.NewTableCell(group).SetReference(group))
				// Maybe: map DN and enrich with some attributes?
			}
		}

		userGroupsPanel.Select(0, 0)
		userGroupsPanel.ScrollToBeginning()
		app.SetFocus(userGroupsPanel)
		updateLog("Groups query completed ("+strconv.Itoa(len(memberOf))+" objects found)", "green")
	})
}

func groupRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case groupMembersPanel:
		app.SetFocus(groupNameInput)
	case groupNameInput:
		app.SetFocus(userNameInput)
	case userNameInput:
		app.SetFocus(userGroupsPanel)
	case userGroupsPanel:
		app.SetFocus(groupMembersPanel)
	}
}

func groupPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		groupRotateFocus()
		return nil
	}

	return event
}
