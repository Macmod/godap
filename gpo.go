package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
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
	runControlGpo sync.Mutex
	runningGpo    bool

	gpoTarget string

	gpoTargetInput *tview.InputField
	gpoPath        *tview.TextView
	gpoPage        *tview.Flex
	gpoListPanel   *tview.Table
	gpoLinksPanel  *tview.Table
	gpoFlex        *tview.Flex

	gpLinks        map[string][]GPOLink
	containerLinks map[string][]string
	gpEntry        map[string]*ldap.Entry
)

type GPOLink struct {
	Target   string
	GUID     string
	Path     string
	Enabled  bool
	Enforced bool
}

func ParseGPLinks(gpoLinks string, target string) ([]GPOLink, error) {
	var links []GPOLink

	re := regexp.MustCompile(`\[LDAP://[cC][nN]=({[A-Fa-f0-9\-]+}),[^;]+;(\d+)\]`)

	matches := re.FindAllStringSubmatch(gpoLinks, -1)

	for _, match := range matches {
		guid := match[1]
		path := match[0][8 : len(match[0])-len(match[2])-1]
		flags, _ := strconv.Atoi(match[2])

		link := GPOLink{
			Target:   target,
			GUID:     guid,
			Path:     path,
			Enabled:  (flags & 0x00000001) == 0,
			Enforced: (flags & 0x00000002) != 0,
		}
		links = append(links, link)
	}

	return links, nil
}

func initGPOPage() {
	gpoTargetInput = tview.NewInputField()
	gpoTargetInput.
		SetPlaceholder("Type a target (DN or cn) or just leave it blank and hit enter").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("GPO Target").
		SetBorder(true)

	gpoListPanel = tview.NewTable().SetSelectable(true, false)

	gpoLinksPanel = tview.NewTable().SetSelectable(true, false)

	gpoPath = tview.NewTextView()
	gpoPath.SetWrap(false)

	gpoPath.
		SetTitle("GPO Path").
		SetBorder(true)

	gpoListPanel.
		SetEvaluateAllRows(true).
		SetTitle("Applied GPOs").
		SetBorder(true)

	gpoLinksPanel.
		SetEvaluateAllRows(true).
		SetTitle("Links").
		SetBorder(true)

	gpoFlex = tview.NewFlex().
		AddItem(gpoListPanel, 0, 1, false).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(gpoPath, 3, 0, false).
				AddItem(gpoLinksPanel, 0, 1, false),
			0, 1, false)

	gpoPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(gpoTargetInput, 3, 0, false).
		AddItem(gpoFlex, 0, 1, false)

	gpoTargetInput.SetDoneFunc(func(key tcell.Key) {
		go updateGPOEntries()
	})

	gpoListPanel.SetSelectedFunc(func(row, col int) {
		app.SetFocus(gpoLinksPanel)
	})

	gpoListPanel.SetSelectionChangedFunc(func(row, col int) {
		if row <= 0 {
			row = 1
		}

		gpoLinksPanel.Clear()
		gpoPath.SetText("")

		guid := gpoListPanel.GetCell(row, 3).Text

		entry, ok := gpEntry[guid]
		if ok {
			gpPath := entry.GetAttributeValue("gPCFileSysPath")
			gpoPath.SetText(gpPath)
		}

		val, ok := gpLinks[guid]
		if ok {
			gpoLinksPanel.SetCell(0, 0, tview.NewTableCell("Target").SetSelectable(false))
			gpoLinksPanel.SetCell(0, 1, tview.NewTableCell("Enforced").SetSelectable(false))
			gpoLinksPanel.SetCell(0, 2, tview.NewTableCell("Enabled").SetSelectable(false))

			idx := 0
			for linkIdx := range val {
				enforced := "[red]No"
				if val[linkIdx].Enforced {
					enforced = "[green]Yes"
				}

				enabled := "[red]No"
				if val[linkIdx].Enabled {
					enabled = "[green]Yes"
				}

				gpoLinksPanel.SetCellSimple(idx+1, 0, val[linkIdx].Target)
				gpoLinksPanel.SetCellSimple(idx+1, 1, enforced)
				gpoLinksPanel.SetCellSimple(idx+1, 2, enabled)
				idx += 1
			}
		}
	})

	gpoLinksPanel.SetSelectedFunc(func(row, col int) {
		targetDN := gpoLinksPanel.GetCell(row, 0).Text

		gpoTargetInput.SetText(targetDN)
		app.SetFocus(gpoTargetInput)
	})

	gpoPage.SetInputCapture(gpoPageKeyHandler)
}

func gpoRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case gpoListPanel:
		app.SetFocus(gpoTargetInput)
	case gpoTargetInput:
		app.SetFocus(gpoPath)
	case gpoPath:
		app.SetFocus(gpoLinksPanel)
	default:
		app.SetFocus(gpoListPanel)
	}
}

func updateGPOEntries() {
	runControlGpo.Lock()
	if runningGpo {
		runControlGpo.Unlock()
		updateLog("Another query is still running...", "yellow")
		return
	}
	runningGpo = true
	runControlGpo.Unlock()

	defer func() {
		runControlGpo.Lock()
		runningGpo = false
		runControlGpo.Unlock()
	}()

	gpLinks = make(map[string][]GPOLink)
	gpEntry = make(map[string]*ldap.Entry)
	containerLinks = make(map[string][]string)

	gpoListPanel.SetTitle("Applied GPOs")
	gpoLinksPanel.Clear()
	gpoListPanel.Clear()
	gpoPath.Clear()

	gpoListPanel.SetCell(0, 0, tview.NewTableCell("Name").SetSelectable(false))
	gpoListPanel.SetCell(0, 1, tview.NewTableCell("Created").SetSelectable(false))
	gpoListPanel.SetCell(0, 2, tview.NewTableCell("Changed").SetSelectable(false))
	gpoListPanel.SetCell(0, 3, tview.NewTableCell("GUID").SetSelectable(false))

	// Load all gpLinks
	updateLog("Querying all gpLinks", "yellow")
	gpLinkObjs, err := lc.Query(lc.RootDN, "(gpLink=*)", ldap.ScopeWholeSubtree, false)

	for _, gpLinkObj := range gpLinkObjs {
		gpLinkVals := gpLinkObj.GetAttributeValue("gPLink")

		links, _ := ParseGPLinks(gpLinkVals, gpLinkObj.DN)

		for _, link := range links {
			gpLinks[link.GUID] = append(gpLinks[link.GUID], link)
			containerLinks[link.Target] = append(containerLinks[link.Target], link.GUID)
		}
	}
	updateLog("gpLinks loaded successfully", "green")

	// Load all GPOs from corresponding links
	gpoQuery := "(objectClass=groupPolicyContainer)"
	gpoTarget = gpoTargetInput.GetText()

	gpoTargetDN := gpoTarget
	if gpoTarget != "" {
		gpoTargetQuery := fmt.Sprintf("(distinguishedName=%s)", ldap.EscapeFilter(gpoTarget))
		if !strings.Contains(gpoTarget, "=") {
			gpoTargetQuery = fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(gpoTarget))
		}

		entries, err := lc.Query(lc.RootDN, gpoTargetQuery, ldap.ScopeWholeSubtree, false)

		updateLog("Querying for '"+gpoTargetQuery+"'", "yellow")
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return
		}

		if len(entries) > 0 {
			updateLog("GPO target found ("+entries[0].DN+")", "green")
			gpoTargetDN = entries[0].DN
		} else {
			updateLog("GPO target not found", "red")
			app.Draw()
			return
		}
	}

	var applicableGPOs []string

	dnParts := strings.Split(gpoTargetDN, ",")
	for idx := len(dnParts) - 1; idx >= 0; idx -= 1 {
		candidateDN := strings.Join(dnParts[idx:], ",")

		candidateGuids, ok := containerLinks[candidateDN]
		if ok {
			applicableGPOs = append(applicableGPOs, candidateGuids...)
		}
	}

	gpoQuerySuffix := ""
	if len(applicableGPOs) > 0 {
		gpoQuerySuffix = "name=" + ldap.EscapeFilter(applicableGPOs[0])
		for _, gpoGuid := range applicableGPOs[1:] {
			gpoQuerySuffix = "(|(" + gpoQuerySuffix + ")(name=" + ldap.EscapeFilter(gpoGuid) + "))"
		}
	}

	if gpoQuerySuffix != "" {
		gpoQuery = "(&(" + gpoQuery + ")(" + gpoQuerySuffix + "))"
	}

	updateLog("Searching applicable GPOs...", "yellow")

	entries, err := lc.Query(lc.RootDN, gpoQuery, ldap.ScopeWholeSubtree, false)
	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		return
	}

	if len(entries) > 0 {
		updateLog("GPOs query completed ("+strconv.Itoa(len(entries))+" GPOs found)", "green")
	} else {
		updateLog("No applicable GPOs found", "red")
	}

	for idx, entry := range entries {
		gpoGuid := entry.GetAttributeValue("cn")
		gpEntry[gpoGuid] = entry

		gpoName := entry.GetAttributeValue("displayName")

		gpoCreated := entry.GetAttributeValue("whenCreated")
		gpoChanged := entry.GetAttributeValue("whenChanged")

		gpoListPanel.SetCellSimple(idx+1, 0, gpoName)
		gpoListPanel.SetCellSimple(idx+1, 1, utils.FormatLDAPTime(gpoCreated))
		gpoListPanel.SetCellSimple(idx+1, 2, utils.FormatLDAPTime(gpoChanged))
		gpoListPanel.SetCellSimple(idx+1, 3, gpoGuid)
	}

	if len(entries) > 0 {
		gpoListPanel.SetTitle("Applied GPOs (" + strconv.Itoa(len(entries)) + ")")
		gpoListPanel.Select(1, 0)

		app.SetFocus(gpoListPanel)
	}

	app.Draw()
}

func exportCurrentGpos() {
	if gpEntry == nil {
		updateLog("An object was not queried yet", "red")
		return
	}

	unixTimestamp := time.Now().UnixMilli()
	outputFilename := fmt.Sprintf("%d_gpos.json", unixTimestamp)

	exportMap := make(map[string]any)

	exportMap["Links"] = gpLinks
	exportMap["Gpos"] = gpEntry
	exportMap["Query"] = gpoTarget

	jsonExportMap, _ := json.MarshalIndent(exportMap, "", " ")

	err := ioutil.WriteFile(outputFilename, jsonExportMap, 0644)

	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	} else {
		updateLog("File '"+outputFilename+"' saved successfully!", "green")
	}
}

func gpoPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		gpoRotateFocus()
		return nil
	}

	switch event.Key() {
	case tcell.KeyCtrlS:
		exportCurrentGpos()
		return nil
	}

	return event
}
