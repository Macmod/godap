package main

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/godap/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var (
	searchTreePanel    *tview.TreeView
	searchQueryPanel   *tview.InputField
	searchLibraryPanel *tview.List
	treeFlex           *tview.Flex
	searchPage         *tview.Flex
)

var searchLoadedDNs map[string]*tview.TreeNode = make(map[string]*tview.TreeNode)

func InitSearchPage() {
	searchQueryPanel = tview.NewInputField().
		SetFieldBackgroundColor(tcell.GetColor("black"))
	searchQueryPanel.SetTitle("Search Filter (Recursive)").SetBorder(true)

	searchLibraryPanel = tview.NewList()
	searchLibraryPanel.SetTitle("Search Library").SetBorder(true)
	searchLibraryPanel.SetCurrentItem(0)

	predefinedLdapQueriesKeys := make([]string, 0)
	for k, _ := range utils.PredefinedLdapQueries {
		predefinedLdapQueriesKeys = append(predefinedLdapQueriesKeys, k)
	}
	sort.Strings(predefinedLdapQueriesKeys)

	for _, key := range predefinedLdapQueriesKeys {
		query := utils.PredefinedLdapQueries[key]
		searchLibraryPanel.AddItem(key, query, 'o', nil)
	}
	searchLibraryPanel.SetSelectedFunc(func(idx int, key string, query string, ch rune) {
		nowTimestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
		editedQuery := strings.Replace(
			strings.Replace(
				query, "DC=domain,DC=com", rootDN, -1,
			),
			"<timestamp>", nowTimestamp, -1,
		)
		searchQueryPanel.SetText(editedQuery)
		searchQueryDoneHandler(tcell.KeyEnter)
	})

	searchQueryPanel.SetDoneFunc(searchQueryDoneHandler)

	searchTreePanel = tview.NewTreeView()
	searchTreePanel.SetTitle("Search Results").SetBorder(true)
	searchTreePanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		currentNode := searchTreePanel.GetCurrentNode()
		if currentNode == nil {
			return event
		}

		switch event.Key() {
		case tcell.KeyRight:
			currentNode.SetExpanded(true)
		case tcell.KeyLeft:
			currentNode.SetExpanded(false)
		}

		return event
	})

	searchPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(searchQueryPanel, 0, 1, false),
			3, 0, false,
		).
		AddItem(
			tview.NewFlex().
				AddItem(searchTreePanel, 0, 2, false).
				AddItem(searchLibraryPanel, 0, 1, false),
			0, 8, false,
		)

	searchPage.SetInputCapture(searchPageKeyHandler)
}

func searchQueryDoneHandler(key tcell.Key) {
	updateLog("Performing recursive query...", "yellow")
	rootNode := tview.NewTreeNode(rootDN).SetSelectable(false)
	searchTreePanel.SetRoot(rootNode).SetCurrentNode(rootNode)

	clear(searchLoadedDNs)

	searchQuery := searchQueryPanel.GetText()
	entries, _ := lc.Query(rootDN, searchQuery, ldap.ScopeWholeSubtree)

	for _, entry := range entries {
		if entry.DN == rootDN {
			continue
		}

		var nodeName string
		entryName := getNodeName(entry)
		dnPath := strings.TrimSuffix(entry.DN, ","+rootDN)

		components := strings.Split(dnPath, ",")
		currentNode := searchTreePanel.GetRoot()

		for i := len(components) - 1; i >= 0; i-- {
			//attribute := strings.Split(components[i], "=")[0]
			//value := strings.Split(components[i], "=")[1]

			partialDN := strings.Join(components[i:], ",")

			childNode, ok := searchLoadedDNs[partialDN]
			if !ok {
				if i == 0 {
					nodeName = entryName
				} else {
					nodeName = components[i]
				}

				childNode = tview.NewTreeNode(nodeName).
					SetSelectable(true).
					SetExpanded(true)
				currentNode.AddChild(childNode)
				searchLoadedDNs[partialDN] = childNode
			}

			currentNode = childNode
		}
	}

	updateLog("Query completed", "green")
}

func searchPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		searchRotateFocus()
		return nil
	}

	return event
}

func searchRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case searchTreePanel:
		app.SetFocus(searchQueryPanel)
	case searchQueryPanel:
		app.SetFocus(searchLibraryPanel)
	case searchLibraryPanel:
		app.SetFocus(searchTreePanel)
	}
}
