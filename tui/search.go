package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
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

	searchCache          EntryCache
	searchHistoryEntries []SearchHistoryEntry

	searchHistoryPanel *tview.Table
)

type SearchHistoryEntry struct {
	Timestamp time.Time
	Query     string
	Duration  time.Duration
	Results   int
}

func addToSearchHistory(query string, duration time.Duration, results int) {
	// Don't add empty queries to history
	if query == "" {
		return
	}

	entry := SearchHistoryEntry{
		Timestamp: time.Now(),
		Query:     query,
		Duration:  duration,
		Results:   results,
	}

	// Add to beginning of slice (most recent first)
	searchHistoryEntries = append([]SearchHistoryEntry{entry}, searchHistoryEntries...)
}

var searchLoadedDNs map[string]*tview.TreeNode = make(map[string]*tview.TreeNode)

func reloadSearchAttrsPanel(node *tview.TreeNode, useCache bool) {
	err := reloadAttributesPanel(node, searchAttrsPanel, useCache, &searchCache)
	if err != nil {
		updateLog(fmt.Sprintf("Error reloading attributes panel: %v", err), "red")
	}
}

func reloadSearchNode(currentNode *tview.TreeNode) {
	baseDN := currentNode.GetReference().(string)

	updateLog("Reloading node "+baseDN, "yellow")
	reloadSearchAttrsPanel(currentNode, false)
	selectAnchoredAttribute(searchAttrsPanel)

	updatedEntry := searchCache.entries[baseDN]
	entryName := getNodeName(updatedEntry)

	if Colors {
		color, _ := GetEntryColor(updatedEntry)
		currentNode.SetColor(color)
	}

	currentNode.SetText(entryName)

	// TODO:
	// Maybe there should be a separate option to also reload the children of the node

	updateLog("Node "+baseDN+" reloaded", "green")
}

func updateSearchHistoryPanel() {
	searchHistoryPanel.Clear()

	searchHistoryPanel.SetCell(0, 0, tview.NewTableCell("StartTime").SetSelectable(false))
	searchHistoryPanel.SetCell(0, 1, tview.NewTableCell("Duration").SetSelectable(false))
	searchHistoryPanel.SetCell(0, 2, tview.NewTableCell("Results").SetSelectable(false))
	searchHistoryPanel.SetCell(0, 3, tview.NewTableCell("Query").SetSelectable(false))

	for i, entry := range searchHistoryEntries {
		row := i + 1

		timestamp := entry.Timestamp.Format(TimeFormat)
		duration := fmt.Sprintf("%.4fs", entry.Duration.Seconds())
		results := strconv.Itoa(entry.Results)

		searchHistoryPanel.SetCell(row, 0, tview.NewTableCell(timestamp))
		searchHistoryPanel.SetCell(row, 1, tview.NewTableCell(duration))
		searchHistoryPanel.SetCell(row, 2, tview.NewTableCell(results))
		searchHistoryPanel.SetCell(row, 3, tview.NewTableCell(entry.Query))
	}
}

func initSearchPage() {
	searchCache = EntryCache{
		entries: make(map[string]*ldap.Entry),
	}

	searchQueryPanel = tview.NewInputField()
	searchQueryPanel.
		SetPlaceholder("Type an LDAP search filter or the name of an object").
		SetTitle("Search Filter (Recursive)").
		SetBorder(true)
	assignInputFieldTheme(searchQueryPanel)

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
		selectAnchoredAttribute(searchAttrsPanel)
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
	searchAttrsPanel.SetSelectionChangedFunc(storeAnchoredAttribute(searchAttrsPanel))

	searchLibraryPanel = tview.NewTreeView()

	searchLibraryRoot := tview.NewTreeNode("Queries").SetSelectable(false)
	searchLibraryPanel.SetRoot(searchLibraryRoot)

	searchHistoryPanel = tview.NewTable().
		SetSelectable(true, false).
		SetBorders(false).
		SetFixed(1, 0)

	searchHistoryPanel.
		SetTitle("Search History")

	searchHistoryPanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			row, _ := searchHistoryPanel.GetSelection()

			if row > 0 && row <= len(searchHistoryEntries) {
				entry := searchHistoryEntries[row-1]
				searchQueryPanel.SetText(entry.Query)
				app.SetFocus(searchQueryPanel)

				return nil
			}
		}

		return event
	})

	sidePanel = tview.NewPages().
		AddPage("page-0", searchLibraryPanel, true, true).
		AddPage("page-1", searchAttrsPanel, true, false).
		AddPage("page-2", searchHistoryPanel, true, false)

	sidePanel.SetBorder(true)

	var predefinedLdapQueriesKeys []string

	var chosenLibrary map[string][]ldaputils.LibQuery

	if lc.Flavor == ldaputils.MicrosoftADFlavor {
		predefinedLdapQueriesKeys = []string{"Security", "Group Members", "Users", "Computers", "Enum"}
		chosenLibrary = ldaputils.PredefinedLdapQueriesAD
	} else {
		predefinedLdapQueriesKeys = []string{"Users", "Groups", "Enum"}
		chosenLibrary = ldaputils.PredefinedLdapQueriesBasic
	}

	for _, key := range predefinedLdapQueriesKeys {
		children := chosenLibrary[key]

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

			editedQuery := strings.ReplaceAll(ref.(string), "DC=domain,DC=com", lc.DefaultRootDN)
			editedQuery = strings.ReplaceAll(editedQuery, "<timestamp>", nowTimestampStr)
			editedQuery = strings.ReplaceAll(editedQuery, "<timestamp1d>", lastDayTimestampStr)
			editedQuery = strings.ReplaceAll(editedQuery, "<timestamp30d>", lastMonthTimestampStr)

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
			exportCacheToFile(currentNode, &searchCache, "results")
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
				openUpdateUacForm(currentNode, &searchCache, func() {
					go app.QueueUpdateDraw(func() {
						reloadSearchNode(currentNode)
					})
				})
			}
		case tcell.KeyCtrlN:
			if currentNode.GetReference() != nil {
				openCreateObjectForm(currentNode, nil)
			}
		case tcell.KeyCtrlG:
			if currentNode.GetReference() != nil {
				baseDN := currentNode.GetReference().(string)
				entry := searchCache.entries[baseDN]
				objClasses := entry.GetAttributeValues("objectClass")
				isGroup := slices.Contains(objClasses, "group")
				openAddMemberToGroupForm(baseDN, isGroup)
			}
		case tcell.KeyCtrlD:
			if currentNode.GetReference() != nil {
				baseDN := currentNode.GetReference().(string)
				info.Highlight("3")
				objectNameInputDacl.SetText(baseDN)
				queryDacl(baseDN)
			}
		}

		switch event.Rune() {
		case 'r', 'R':
			if currentNode.GetReference() != nil {
				go app.QueueUpdateDraw(func() {
					reloadSearchNode(currentNode)
				})
			}
		}

		return event
	})

	_, _ = fmt.Fprintf(tabs, `["%s"][white]%s[black][""] `, "0", "Library")
	_, _ = fmt.Fprintf(tabs, `["%s"][white]%s[black][""] `, "1", "Attrs")
	_, _ = fmt.Fprintf(tabs, `["%s"][white]%s[black][""]`, "2", "History")

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
				AddItem(tabs, 23, 0, false),
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

	rootNode := tview.NewTreeNode(lc.DefaultRootDN).SetSelectable(true)
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

		if searchQuery != "" && !strings.Contains(searchQuery, "(") {
			searchQuery = fmt.Sprintf(
				"(|(samAccountName=%s)(cn=%s)(ou=%s)(name=%s))",
				searchQuery, searchQuery, searchQuery, searchQuery,
			)
		}

		startTime := time.Now()

		entries, _ := lc.Query(lc.DefaultRootDN, searchQuery, ldap.ScopeWholeSubtree, Deleted)

		duration := time.Since(startTime)

		firstLeaf := true

		for _, entry := range entries {
			if entry.DN == lc.DefaultRootDN {
				continue
			}

			var nodeName string
			entryName := getNodeName(entry)
			dnPath := strings.TrimSuffix(entry.DN, ","+lc.DefaultRootDN)

			components := strings.Split(dnPath, ",")
			currentNode := searchTreePanel.GetRoot()

			for i := len(components) - 1; i >= 0; i-- {
				partialDN := strings.Join(components[i:], ",")

				childNode, ok := searchLoadedDNs[partialDN]
				if !ok {
					app.QueueUpdateDraw(func() {
						if i == 0 {
							// Leaf node
							nodeName = entryName
							childNode = tview.NewTreeNode(nodeName).
								SetReference(entry.DN).
								SetExpanded(false).
								SetSelectable(true)

							if Colors {
								color, changed := GetEntryColor(entry)
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
					})

					searchLoadedDNs[partialDN] = childNode
				}

				currentNode = childNode
			}
		}

		app.QueueUpdateDraw(func() {
			updateLog(
				fmt.Sprintf("Query completed (%d objects found in %.4fs)", len(entries), duration.Seconds()), "green")
		})

		addToSearchHistory(searchQuery, duration, len(entries))
		app.QueueUpdateDraw(func() {
			updateSearchHistoryPanel()
		})

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
	case searchLibraryPanel, searchAttrsPanel, searchHistoryPanel:
		app.SetFocus(searchTreePanel)
	}
}
