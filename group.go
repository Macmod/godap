package main

import (
	"fmt"
	"github.com/Macmod/godap/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
	"strings"
)

var groupPage *tview.Flex
var groupNameInput *tview.InputField
var groupMembersPanel *tview.Table
var userNameInput *tview.InputField
var userGroupsPanel *tview.Table

func InitGroupPage() {
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
		}
	})

	groupPage = tview.NewFlex().
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(groupNameInput, 0, 1, false).
				AddItem(groupMembersPanel, 0, 8, false),
			0, 1, false,
		).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(userNameInput, 0, 1, false).
				AddItem(userGroupsPanel, 0, 8, false),
			0, 1, false,
		)

	groupPage.SetInputCapture(groupPageKeyHandler)
	groupNameInput.SetDoneFunc(func(key tcell.Key) {
		groupMembersPanel.Clear()

		entries, err := queryGroupMembers(groupNameInput.GetText())
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

		updateLog("Group members query executed successfully", "green")
	})

	userNameInput.SetDoneFunc(func(key tcell.Key) {
		userGroupsPanel.Clear()

		entries, err := queryUserGroups(userNameInput.GetText())
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		for _, entry := range entries {
			memberOf := entry.GetAttributeValues("memberOf")

			for idx, group := range memberOf {
				userGroupsPanel.SetCell(idx, 0, tview.NewTableCell(group).SetReference(group))
				// Maybe: map DN and enrich with some attributes?
			}
		}

		updateLog("User groups query executed successfully", "green")
	})
}

func queryGroupMembers(groupName string) (group []*ldap.Entry, err error) {
	groupDNQuery := fmt.Sprintf("(&(objectCategory=group)(sAMAccountName=%s))", groupName)

	groupDN := groupName
	if !strings.Contains(groupName, ",") {
		groupSearch := ldap.NewSearchRequest(
			rootDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			groupDNQuery,
			[]string{"distinguishedName"},
			nil,
		)

		groupResult, err := conn.Search(groupSearch)
		if err != nil {
			return nil, err
		}

		if len(groupResult.Entries) == 0 {
			return nil, fmt.Errorf("Group '%s' not found", groupName)
		}

		groupDN = groupResult.Entries[0].GetAttributeValue("distinguishedName")
	}

	ldapQuery := fmt.Sprintf("(memberOf=%s)", groupDN)

	search := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapQuery,
		[]string{"sAMAccountName", "objectCategory"},
		nil,
	)

	result, err := conn.Search(search)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("Group '%s' not found", groupName)
	}

	return result.Entries, nil
}

func queryUserGroups(userName string) ([]*ldap.Entry, error) {
	var ldapQuery string
	if !strings.Contains(userName, ",") {
		ldapQuery = fmt.Sprintf("(sAMAccountName=%s)", userName)
	} else {
		ldapQuery = fmt.Sprintf("(distinguishedName=%s)", userName)
	}

	search := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapQuery,
		[]string{"memberOf"},
		nil,
	)

	result, err := conn.Search(search)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("User '%s' not found", userName)
	}

	return result.Entries, nil
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
