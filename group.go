package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/godap/v2/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var (
	groupPage      *tview.Flex
	groupNameInput *tview.InputField
	membersPanel   *tview.Table
	userNameInput  *tview.InputField
	groupsPanel    *tview.Table

	groups  []string
	members []*ldap.Entry

	queryGroup  string
	queryObject string
	groupDN     string
	objectDN    string
)

func initGroupPage() {
	groupNameInput = tview.NewInputField()
	groupNameInput.
		SetPlaceholder("Type a group's name or DN").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("Group").
		SetBorder(true)

	userNameInput = tview.NewInputField()
	userNameInput.
		SetPlaceholder("Type a user's sAMAccountName or DN").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("User").
		SetBorder(true)

	membersPanel = tview.NewTable()
	membersPanel.
		SetSelectable(true, false).
		SetTitle("Group Members").
		SetBorder(true)

	membersPanel.SetSelectedFunc(func(row, col int) {
		cell := membersPanel.GetCell(row, col)
		cellId, ok := cell.GetReference().(string)
		if ok {
			userNameInput.SetText(cellId)
			app.SetFocus(userNameInput)
		}
	})

	groupsPanel = tview.NewTable()
	groupsPanel.
		SetSelectable(true, false).
		SetTitle("User Groups").
		SetBorder(true)
	groupsPanel.SetSelectedFunc(func(row, col int) {
		cell := groupsPanel.GetCell(row, col)
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
				AddItem(membersPanel, 0, 8, false),
			0, 1, false,
		).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(userNameInput, 3, 0, false).
				AddItem(groupsPanel, 0, 8, false),
			0, 1, false,
		)

	groupPage.SetInputCapture(groupPageKeyHandler)
	membersPanel.SetInputCapture(membersKeyHandler)
	groupsPanel.SetInputCapture(groupsKeyHandler)

	groupNameInput.SetDoneFunc(func(key tcell.Key) {
		membersPanel.Clear()

		queryGroup = groupNameInput.GetText()
		samOrDn, isSam := utils.SamOrDN(queryGroup)

		groupDN = queryGroup
		if isSam {
			groupDNQuery := fmt.Sprintf("(&(objectCategory=group)%s)", samOrDn)
			groupEntries, err := lc.Query(lc.RootDN, groupDNQuery, ldap.ScopeWholeSubtree, false)
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
				return
			}

			if len(groupEntries) == 0 {
				updateLog(fmt.Sprintf("Group '%s' not found", queryGroup), "red")
				return
			}

			groupDN = groupEntries[0].DN
		}

		members, err = lc.QueryGroupMembers(groupDN)
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

			membersPanel.SetCell(idx, 0, tview.NewTableCell(sAMAccountName).SetReference(entry.DN))
			membersPanel.SetCell(idx, 1, tview.NewTableCell(category).SetReference(entry.DN))
			membersPanel.SetCell(idx, 2, tview.NewTableCell(entry.DN).SetReference(entry.DN))
		}

		membersPanel.Select(0, 0)
		membersPanel.ScrollToBeginning()

		app.SetFocus(membersPanel)
	})

	userNameInput.SetDoneFunc(func(key tcell.Key) {
		groupsPanel.Clear()

		queryObject = userNameInput.GetText()
		entries, err := lc.QueryUserGroups(queryObject)
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		objectDN = queryObject
		if len(entries) > 0 {
			objectDN = entries[0].DN

			groups = entries[0].GetAttributeValues("memberOf")
			updateLog("Found "+strconv.Itoa(len(groups))+" groups containing '"+objectDN+"'", "green")

			for idx, group := range groups {
				groupsPanel.SetCell(idx, 0, tview.NewTableCell(group).SetReference(group))
				// Maybe: map DN and enrich with some attributes?
			}
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
		app.SetFocus(userNameInput)
	case userNameInput:
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

	unixTimestamp := time.Now().UnixMilli()
	outputFilename := fmt.Sprintf("%d_groups.json", unixTimestamp)

	exportMap := make(map[string]any)
	exportMap["Groups"] = groups
	exportMap["DN"] = objectDN
	exportMap["Query"] = queryObject

	jsonExportMap, _ := json.MarshalIndent(exportMap, "", " ")

	err := ioutil.WriteFile(outputFilename, jsonExportMap, 0644)

	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	} else {
		updateLog("File '"+outputFilename+"' saved successfully!", "green")
	}
}

func exportCurrentMembers() {
	if members == nil {
		updateLog("An object was not queried yet", "red")
		return
	}

	unixTimestamp := time.Now().UnixMilli()
	outputFilename := fmt.Sprintf("%d_members.json", unixTimestamp)

	exportMap := make(map[string]any)
	exportMap["Members"] = members
	exportMap["DN"] = groupDN
	exportMap["Query"] = queryGroup

	jsonExportMap, _ := json.MarshalIndent(exportMap, "", " ")

	err := ioutil.WriteFile(outputFilename, jsonExportMap, 0644)

	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	} else {
		updateLog("File '"+outputFilename+"' saved successfully!", "green")
	}
}

func groupsKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyCtrlS:
		exportCurrentGroups()
		return nil
	}

	return event
}

func membersKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyCtrlS:
		exportCurrentMembers()
		return nil
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
