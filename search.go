package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
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
	runControl         sync.Mutex
	running            bool
)

var searchLoadedDNs map[string]*tview.TreeNode = make(map[string]*tview.TreeNode)

func initSearchPage() {
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
		runControl.Lock()
		if running {
			runControl.Unlock()
			updateLog("Another query is still running...", "yellow")
			return
		}
		runControl.Unlock()

		nowTimestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
		editedQuery := strings.Replace(
			strings.Replace(
				query, "DC=domain,DC=com", lc.RootDN, -1,
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

	rootNode := tview.NewTreeNode(lc.RootDN).SetSelectable(false)
	searchTreePanel.SetRoot(rootNode).SetCurrentNode(rootNode)

	clear(searchLoadedDNs)

	searchQuery := searchQueryPanel.GetText()

	go func() {
		runControl.Lock()
		if running {
			runControl.Unlock()
			return
		}
		running = true
		runControl.Unlock()

		entries, _ := lc.Query(lc.RootDN, searchQuery, ldap.ScopeWholeSubtree)

		for _, entry := range entries {
			if entry.DN == lc.RootDN {
				continue
			}

			var nodeName string
			entryName := getNodeName(entry)
			dnPath := strings.TrimSuffix(entry.DN, ","+lc.RootDN)

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
					app.Draw()

					searchLoadedDNs[partialDN] = childNode
				}

				currentNode = childNode
			}
		}

		updateLog("Query completed ("+strconv.Itoa(len(entries))+" objects found)", "green")
		app.Draw()

		runControl.Lock()
		running = false
		runControl.Unlock()
	}()
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
