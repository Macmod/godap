package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Macmod/godap/v2/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var (
	searchTreePanel  *tview.TreeView
	searchQueryPanel *tview.InputField
	searchAttrsPanel *tview.Table

	searchLibraryPanel *tview.TreeView
	sidePanel          *tview.Pages
	searchPage         *tview.Flex
	runControl         sync.Mutex
	running            bool

	searchCache EntryCache
)

var searchLoadedDNs map[string]*tview.TreeNode = make(map[string]*tview.TreeNode)

func reloadSearchAttrsPanel(node *tview.TreeNode, useCache bool) {
	reloadAttributesPanel(node, searchAttrsPanel, useCache, &searchCache)
}

func initSearchPage() {
	searchCache = EntryCache{
		entries: make(map[string]*ldap.Entry),
	}

	searchQueryPanel = tview.NewInputField()
	searchQueryPanel.
		SetPlaceholder("Type an LDAP search filter").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("Search Filter (Recursive)").
		SetBorder(true)

	tabs := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetWrap(false).
		SetRegions(true).
		SetDynamicColors(true)
	tabs.SetBackgroundColor(tcell.ColorBlack)
	tabs.SetBorder(true)

	searchTreePanel = tview.NewTreeView()
	searchTreePanel.
		SetTitle("Search Results").
		SetBorder(true)

	searchTreePanel.SetChangedFunc(func(node *tview.TreeNode) {
		searchAttrsPanel.Clear()
		reloadSearchAttrsPanel(node, true)
	})

	searchAttrsPanel = tview.NewTable().
		SetSelectable(true, true).
		SetEvaluateAllRows(true)
	searchAttrsPanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		currentNode := searchTreePanel.GetCurrentNode()
		if currentNode == nil || currentNode.GetReference() == nil {
			return event
		}

		return attrsPanelKeyHandler(event, currentNode, &searchCache, searchAttrsPanel)
	})

	searchLibraryPanel = tview.NewTreeView()

	searchLibraryRoot := tview.NewTreeNode("Queries").SetSelectable(false)
	searchLibraryPanel.SetRoot(searchLibraryRoot)

	sidePanel = tview.NewPages().
		AddPage("page-0", searchLibraryPanel, true, true).
		AddPage("page-1", searchAttrsPanel, true, false)

	sidePanel.SetBorder(true)

	predefinedLdapQueriesKeys := []string{"Security", "Users", "Computers", "Enum"}

	for _, key := range predefinedLdapQueriesKeys {
		children := utils.PredefinedLdapQueries[key]

		childNode := tview.NewTreeNode(key).
			SetSelectable(false).
			SetExpanded(true)

		for _, val := range children {
			childNode.AddChild(
				tview.NewTreeNode(val.Title).
					SetReference(val.Filter).
					SetSelectable(true))
		}

		searchLibraryRoot.AddChild(childNode)
	}

	searchLibraryPanel.SetSelectedFunc(
		func(node *tview.TreeNode) {
			runControl.Lock()
			if running {
				runControl.Unlock()
				updateLog("Another query is still running...", "yellow")
				return
			}
			runControl.Unlock()

			searchQueryDoneHandler(tcell.KeyEnter)
		},
	)

	searchLibraryPanel.SetChangedFunc(
		func(node *tview.TreeNode) {
			ref := node.GetReference()
			if ref == nil {
				searchQueryPanel.SetText("")
				return
			}

			nowTimestamp := time.Now().UnixNano()

			nowTimestampStr := strconv.FormatInt(nowTimestamp, 10)
			lastDayTimestampStr := strconv.FormatInt(nowTimestamp-86400, 10)
			lastMonthTimestampStr := strconv.FormatInt(nowTimestamp-2592000, 10)

			editedQuery := strings.Replace(ref.(string), "DC=domain,DC=com", lc.RootDN, -1)
			editedQuery = strings.Replace(editedQuery, "<timestamp>", nowTimestampStr, -1)
			editedQuery = strings.Replace(editedQuery, "<timestamp1d>", lastDayTimestampStr, -1)
			editedQuery = strings.Replace(editedQuery, "<timestamp30d>", lastMonthTimestampStr, -1)

			searchQueryPanel.SetText(editedQuery)
		},
	)

	searchQueryPanel.SetDoneFunc(searchQueryDoneHandler)

	searchTreePanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		currentNode := searchTreePanel.GetCurrentNode()
		if currentNode == nil {
			return event
		}

		switch event.Key() {
		case tcell.KeyRight:
			if len(currentNode.GetChildren()) != 0 && !currentNode.IsExpanded() {
				currentNode.SetExpanded(true)
			}
			return nil
		case tcell.KeyLeft:
			if currentNode.IsExpanded() { // Collapse current node
				currentNode.SetExpanded(false)
				searchTreePanel.SetCurrentNode(currentNode)
			} else { // Collapse parent node
				pathToCurrent := searchTreePanel.GetPath(currentNode)
				if len(pathToCurrent) > 1 {
					parentNode := pathToCurrent[len(pathToCurrent)-2]
					parentNode.SetExpanded(false)
					searchTreePanel.SetCurrentNode(parentNode)
				}
			}
			return nil
		case tcell.KeyDelete:
			if currentNode.GetReference() != nil {
				openDeleteObjectForm(currentNode, nil)
			}
		case tcell.KeyCtrlS:
			unixTimestamp := time.Now().UnixMilli()
			outputFilename := fmt.Sprintf("%d_results.json", unixTimestamp)
			exportCacheToFile(currentNode, &searchCache, outputFilename)
		case tcell.KeyCtrlP:
			if currentNode.GetReference() != nil {
				openPasswordChangeForm(currentNode)
			}
		case tcell.KeyCtrlL:
			if currentNode.GetReference() != nil {
				openMoveObjectForm(currentNode, nil)
			}
		case tcell.KeyCtrlA:
			if currentNode.GetReference() != nil {
				openUpdateUacForm(currentNode, &searchCache, nil)
			}
		case tcell.KeyCtrlN:
			if currentNode.GetReference() != nil {
				openCreateObjectForm(currentNode, nil)
			}
		case tcell.KeyCtrlG:
			if currentNode.GetReference() != nil {
				baseDN := currentNode.GetReference().(string)
				openAddMemberToGroupForm(baseDN)
			}
		}

		return event
	})

	fmt.Fprintf(tabs, `["%s"][white]%s[black][""] `, "0", "Library")
	fmt.Fprintf(tabs, `["%s"][white]%s[black][""]`, "1", "Attributes")

	tabs.SetHighlightedFunc(func(added, removed, remaining []string) {
		if len(added) > 0 {
			sidePanel.SwitchToPage("page-" + added[0])
		} else {
			tabs.Highlight("0")
		}
	})

	tabs.Highlight("0")

	searchPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(searchQueryPanel, 0, 1, false).
				AddItem(tabs, 20, 0, false),
			3, 0, false,
		).
		AddItem(
			tview.NewFlex().
				AddItem(searchTreePanel, 0, 1, false).
				AddItem(sidePanel, 0, 1, false),
			0, 8, false,
		)

	searchPage.SetInputCapture(searchPageKeyHandler)
}

func searchQueryDoneHandler(key tcell.Key) {
	updateLog("Performing recursive query...", "yellow")

	rootNode := tview.NewTreeNode(lc.RootDN).SetSelectable(true)
	searchTreePanel.
		SetRoot(rootNode).
		SetCurrentNode(rootNode)

	searchCache.Clear()
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

		entries, _ := lc.Query(lc.RootDN, searchQuery, ldap.ScopeWholeSubtree, deleted)

		firstLeaf := true

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
				partialDN := strings.Join(components[i:], ",")

				childNode, ok := searchLoadedDNs[partialDN]
				if !ok {
					if i == 0 {
						// Leaf node
						nodeName = entryName
						childNode = tview.NewTreeNode(nodeName).
							SetReference(entry.DN).
							SetExpanded(false).
							SetSelectable(true)

						if colors {
							color, changed := utils.GetEntryColor(entry)
							if changed {
								childNode.SetColor(color)
							}
						}
						currentNode.AddChild(childNode)

						if firstLeaf {
							searchTreePanel.SetCurrentNode(childNode)
							firstLeaf = false
						}

						searchCache.Add(entry.DN, entry)
					} else {
						// Non-leaf node
						nodeName = components[i]
						childNode = tview.NewTreeNode(nodeName).
							SetExpanded(true).
							SetSelectable(true)
						currentNode.AddChild(childNode)
					}

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

	switch event.Key() {
	case tcell.KeyCtrlF:
		openFinder(&searchCache, "Object Search")
	}

	return event
}

func searchRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case searchTreePanel:
		app.SetFocus(searchQueryPanel)
	case searchQueryPanel:
		app.SetFocus(sidePanel)
	case searchLibraryPanel, searchAttrsPanel:
		app.SetFocus(searchTreePanel)
	}
}
