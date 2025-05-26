package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var (
	groupPage       *tview.Flex
	groupNameInput  *tview.InputField
	membersPanel    *tview.Table
	objectNameInput *tview.InputField
	groupsPanel     *tview.Table
	depthInput      *tview.InputField

	groups   []*ldap.Entry
	members  []*ldap.Entry
	maxDepth int

	queryGroup  string
	queryObject string
	groupDN     string
	objectDN    string
)

func openRemoveMemberFromGroupForm(targetDN string, groupDN string) {
	currentFocus := app.GetFocus()

	confirmText := fmt.Sprintf(
		"Do you really want to remove this member from this group?\nMember: %s\nGroup: %s",
		targetDN, groupDN,
	)

	promptModal := tview.NewModal().
		SetText(confirmText).
		AddButtons([]string{"No", "Yes"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				err := lc.RemoveMemberFromGroup(targetDN, groupDN)
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
				} else {
					updateLog(fmt.Sprintf("Member %s removed from group %s", targetDN, groupDN), "green")
				}
			}

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		})

	app.SetRoot(promptModal, true).SetFocus(promptModal)
}

func updateMaxDepth() {
	depthStr := depthInput.GetText()

	if depthStr == "" {
		maxDepth = 0
	} else {
		maxDepth, err = strconv.Atoi(depthStr)
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}
	}
}

func initGroupPage() {
	groupNameInput = tview.NewInputField()
	groupNameInput.
		SetPlaceholder("Type a group's name or DN").
		SetTitle("Group").
		SetBorder(true)
	assignInputFieldTheme(groupNameInput)

	objectNameInput = tview.NewInputField()
	objectNameInput.
		SetPlaceholder("Type an object's sAMAccountName or DN").
		SetTitle("Object").
		SetBorder(true)
	assignInputFieldTheme(objectNameInput)

	depthInput = tview.NewInputField()
	depthInput.
		SetText("0").
		SetAcceptanceFunc(tview.InputFieldInteger).
		SetPlaceholder("Maximum depth to query for nested groups (-1 for all nested members)").
		SetTitle("MaxDepth").
		SetBorder(true)
	assignInputFieldTheme(depthInput)

	membersPanel = tview.NewTable()
	membersPanel.
		SetSelectable(true, false).
		SetTitle("Group Members").
		SetBorder(true)

	membersPanel.SetSelectedFunc(func(row, col int) {
		cell := membersPanel.GetCell(row, col)
		cellId, ok := cell.GetReference().(string)
		if ok {
			objectNameInput.SetText(cellId)
			app.SetFocus(objectNameInput)
		}
	})

	groupsPanel = tview.NewTable()
	groupsPanel.
		SetSelectable(true, false).
		SetTitle("Object Groups").
		SetBorder(true)
	groupsPanel.SetSelectedFunc(func(row, col int) {
		cell := groupsPanel.GetCell(row, col)
		cellId, ok := cell.GetReference().(string)
		if ok {
			groupNameInput.SetText(cellId)
			app.SetFocus(groupNameInput)
		}
	})

	groupPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(depthInput, 3, 0, false).
		AddItem(
			tview.NewFlex().
				AddItem(groupNameInput, 0, 1, false).
				AddItem(objectNameInput, 0, 1, false),
			3, 0, false,
		).
		AddItem(
			tview.NewFlex().
				AddItem(membersPanel, 0, 1, false).
				AddItem(groupsPanel, 0, 1, false),
			0, 1, false,
		)

	groupPage.SetInputCapture(groupPageKeyHandler)
	membersPanel.SetInputCapture(membersKeyHandler)
	groupsPanel.SetInputCapture(groupsKeyHandler)

	groupNameInput.SetDoneFunc(func(key tcell.Key) {
		updateMaxDepth()
		membersPanel.Clear()

		queryGroup = groupNameInput.GetText()

		groupDN = queryGroup
		samOrDn, isSam := ldaputils.SamOrDN(queryGroup)
		if isSam {
			groupDNQuery := fmt.Sprintf("(&(objectCategory=group)%s)", samOrDn)
			result, err := lc.QueryFirst(groupDNQuery)
			if err != nil {
				updateLog(fmt.Sprintf("Group '%s' not found", queryGroup), "red")
				return
			}

			groupDN = result.DN
		}

		members, err = lc.QueryGroupMembersDeep(groupDN, maxDepth)
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		updateLog("Found "+strconv.Itoa(len(members))+" members of '"+groupDN+"'", "green")

		for idx, entry := range members {
			sAMAccountName := entry.GetAttributeValue("sAMAccountName")
			categoryDN := strings.Split(entry.GetAttributeValue("objectCategory"), ",")
			var category string
			if len(categoryDN) > 0 {
				category = categoryDN[0]
				if Emojis {
					switch category {
					case "CN=Person":
						category = ldaputils.EmojiMap["person"]
					case "CN=Group":
						category = ldaputils.EmojiMap["group"]
					case "CN=Computer":
						category = ldaputils.EmojiMap["computer"]
					}
				}
			} else {
				category = "Unknown"
			}

			membersPanel.SetCell(idx, 0, tview.NewTableCell(sAMAccountName).SetReference(entry.DN))
			membersPanel.SetCell(idx, 1, tview.NewTableCell(category).SetReference(entry.DN))
			membersPanel.SetCell(idx, 2, tview.NewTableCell(entry.DN).SetReference(entry.DN))
		}

		membersPanel.Select(0, 0)
		membersPanel.ScrollToBeginning()

		app.SetFocus(membersPanel)
	})

	objectNameInput.SetDoneFunc(func(key tcell.Key) {
		updateMaxDepth()
		groupsPanel.Clear()

		queryObject = objectNameInput.GetText()
		objectDN = queryObject

		result, err := lc.FindFirst(queryObject)
		if err != nil {
			updateLog(fmt.Sprintf("Object '%s' not found", queryObject), "red")
			return
		} else {
			objectDN = result.DN
		}

		groups, err = lc.QueryObjectGroupsDeep(objectDN, maxDepth)
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		updateLog("Found "+strconv.Itoa(len(groups))+" groups containing '"+objectDN+"'", "green")

		for idx, group := range groups {
			groupName := group.GetAttributeValue("name")
			groupDN := group.DN
			groupsPanel.SetCell(idx, 0, tview.NewTableCell(groupName).SetReference(group.DN))
			groupsPanel.SetCell(idx, 1, tview.NewTableCell("👥").SetReference(group.DN))
			groupsPanel.SetCell(idx, 2, tview.NewTableCell(groupDN).SetReference(group.DN))
		}

		groupsPanel.Select(0, 0)
		groupsPanel.ScrollToBeginning()
		app.SetFocus(groupsPanel)
	})
}

func groupRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case membersPanel:
		app.SetFocus(groupNameInput)
	case groupNameInput:
		app.SetFocus(depthInput)
	case depthInput:
		app.SetFocus(objectNameInput)
	case objectNameInput:
		app.SetFocus(groupsPanel)
	case groupsPanel:
		app.SetFocus(membersPanel)
	}
}

func exportCurrentGroups() {
	if groups == nil {
		updateLog("An object was not queried yet", "red")
		return
	}

	exportMap := make(map[string]any)
	exportMap["Groups"] = groups
	exportMap["DN"] = objectDN
	exportMap["Query"] = queryObject
	exportMap["MaxDepth"] = maxDepth

	writeDataExport(exportMap, "groups", "object_groups")
}

func exportCurrentMembers() {
	if members == nil {
		updateLog("An object was not queried yet", "red")
		return
	}

	exportMap := make(map[string]any)
	exportMap["Members"] = members
	exportMap["DN"] = groupDN
	exportMap["Query"] = queryGroup
	exportMap["MaxDepth"] = maxDepth

	writeDataExport(exportMap, "members", "group_members")
}

func groupsKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	row, col := groupsPanel.GetSelection()

	switch event.Key() {
	case tcell.KeyCtrlS:
		exportCurrentGroups()
		return nil
	case tcell.KeyDelete:
		selCell := groupsPanel.GetCell(row, col)
		if selCell != nil && selCell.GetReference() != nil {
			otherGroupDN := selCell.GetReference().(string)
			openRemoveMemberFromGroupForm(objectDN, otherGroupDN)
		}
	case tcell.KeyCtrlG:
		selCell := groupsPanel.GetCell(row, col)
		if selCell != nil && selCell.GetReference() != nil {
			baseDN := selCell.GetReference().(string)
			openAddMemberToGroupForm(baseDN, true)
		}
		return nil
	case tcell.KeyCtrlD:
		selCell := groupsPanel.GetCell(row, col)
		if selCell != nil && selCell.GetReference() != nil {
			baseDN := selCell.GetReference().(string)
			info.Highlight("3")
			objectNameInputDacl.SetText(baseDN)
			queryDacl(baseDN)
		}
	}

	return event
}

func membersKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	row, col := membersPanel.GetSelection()

	switch event.Key() {
	case tcell.KeyCtrlS:
		exportCurrentMembers()
		return nil
	case tcell.KeyDelete:
		selCell := membersPanel.GetCell(row, col)
		if selCell != nil && selCell.GetReference() != nil {
			baseDN := selCell.GetReference().(string)
			openRemoveMemberFromGroupForm(baseDN, groupDN)
		}
	case tcell.KeyCtrlG:
		selCell := membersPanel.GetCell(row, col)
		if selCell != nil && selCell.GetReference() != nil {
			baseDN := selCell.GetReference().(string)
			openAddMemberToGroupForm(baseDN, false)
		}
		return nil
	case tcell.KeyCtrlD:
		selCell := membersPanel.GetCell(row, col)
		if selCell != nil && selCell.GetReference() != nil {
			baseDN := selCell.GetReference().(string)
			info.Highlight("3")
			objectNameInputDacl.SetText(baseDN)
			queryDacl(baseDN)
		}
	}

	return event
}

func groupPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		groupRotateFocus()
		return nil
	}

	return event
}
