package tui

/*
{Reference}
- [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a
*/

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Macmod/godap/v2/pkg/adidns"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	dnsTreePanel  *tview.TreeView
	dnsQueryPanel *tview.InputField

	dnsSidePanel   *tview.Pages
	dnsZoneProps   *tview.Table
	dnsNodeRecords *tview.TreeView

	dnsNodeFilter *tview.InputField
	dnsZoneFilter *tview.InputField

	dnsPage *tview.Flex

	dnsRunControl sync.Mutex
	dnsRunning    bool
)

var domainZones []adidns.DNSZone
var forestZones []adidns.DNSZone

var zoneCache = make(map[string]adidns.DNSZone, 0)
var nodeCache = make(map[string]adidns.DNSNode, 0)

func getParentZone(objectDN string) (adidns.DNSZone, error) {
	objectDNParts := strings.Split(objectDN, ",")

	zone, zoneOk := zoneCache[objectDN]
	if zoneOk {
		return zone, nil
	}

	if len(objectDNParts) > 1 {
		parentZoneDN := strings.Join(objectDNParts[1:], ",")
		parentZone, zoneOk := zoneCache[parentZoneDN]
		if zoneOk {
			return parentZone, nil
		} else {
			return adidns.DNSZone{}, fmt.Errorf("Parent zone not found in the cache")
		}
	}

	return adidns.DNSZone{}, fmt.Errorf("Malformed object DN")
}

func exportADIDNSToFile(currentNode *tview.TreeNode, outputFilename string) {
	exportMap := make(map[string]any)

	currentNode.Walk(func(node, parent *tview.TreeNode) bool {
		if node.GetReference() != nil {
			objectDN := node.GetReference().(string)

			zone, zoneOk := zoneCache[objectDN]
			node, nodeOk := nodeCache[objectDN]

			nodesMap := make(map[string]any, 0)

			if zoneOk {
				zoneProps := make(map[string]any, 0)
				for _, prop := range zone.Props {
					propName := adidns.FindPropName(prop.Id)
					zoneProps[propName] = prop.ExportFormat()
				}

				exportMap[objectDN] = map[string]any{
					"Zone": map[string]any{
						"Name":  zone.Name,
						"DN":    zone.DN,
						"Props": zoneProps,
					},
					"Nodes": nodesMap,
				}
			} else if nodeOk {
				records := node.Records

				recordsObj := make([]any, 0)
				for _, rec := range records {
					recordType := rec.PrintType()
					recordsObj = append(recordsObj, map[string]any{
						"Type":  recordType,
						"Value": rec,
					})
				}

				parentZone, err := getParentZone(objectDN)
				if err == nil {
					// Since we're walking the tree it's safe to assume that
					// zones will come before their child nodes, therefore
					// all zone exports will fall in the alreadyExported branch
					// The only way to get the other branch (alreadyExported) is if
					// the user exports a node itself, in which case
					// we must fetch the parent zone's properties
					// to include in the export
					_, alreadyExported := exportMap[parentZone.DN]
					if !alreadyExported {
						parentZoneProps := make(map[string]any, 0)
						for _, prop := range parentZone.Props {
							propName := adidns.FindPropName(prop.Id)
							parentZoneProps[propName] = prop.ExportFormat()
						}

						exportMap[parentZone.DN] = map[string]any{
							"Zone": map[string]any{
								"Name":  parentZone.Name,
								"DN":    parentZone.DN,
								"Props": parentZoneProps,
							},
							"Nodes": nodesMap,
						}
					}

					parentZone := (exportMap[parentZone.DN]).(map[string]any)
					parentZoneNodes := parentZone["Nodes"].(map[string]any)
					parentZoneNodes[node.DN] = map[string]any{
						"Name":    node.Name,
						"Records": recordsObj,
					}
				}
			}
		}
		return true
	})

	jsonExportMap, _ := json.MarshalIndent(exportMap, "", " ")

	err := ioutil.WriteFile(outputFilename, jsonExportMap, 0644)

	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	} else {
		updateLog("File '"+outputFilename+"' saved successfully!", "green")
	}
}

func showZoneDetails(zone *adidns.DNSZone) {
	dnsSidePanel.SetTitle("Zone Properties")
	dnsSidePanel.SwitchToPage("zone-props")

	propsMap := make(map[uint32]adidns.DNSProperty, 0)
	for _, prop := range zone.Props {
		propsMap[prop.Id] = prop
	}

	dnsZoneProps.SetCell(0, 0, tview.NewTableCell("Id").SetSelectable(false))
	dnsZoneProps.SetCell(0, 1, tview.NewTableCell("Description").SetSelectable(false))
	dnsZoneProps.SetCell(0, 2, tview.NewTableCell("Value").SetSelectable(false))

	idx := 1
	for _, prop := range adidns.DnsPropertyIds {
		dnsZoneProps.SetCell(idx, 0, tview.NewTableCell(fmt.Sprint(prop.Id)))
		dnsZoneProps.SetCell(idx, 1, tview.NewTableCell(prop.Name))

		mappedProp, ok := propsMap[prop.Id]
		if ok {
			mappedPropStr := fmt.Sprintf("%v", mappedProp.Data)
			if FormatAttrs {
				mappedPropStr = mappedProp.PrintFormat(TimeFormat)
			}

			if Colors {
				color, change := adidns.GetPropCellColor(mappedProp.Id, mappedPropStr)
				if change {
					mappedPropStr = fmt.Sprintf("[%s]%s[c]", color, mappedPropStr)
				}
			}

			dnsZoneProps.SetCell(idx, 2, tview.NewTableCell(mappedPropStr))
		} else {
			notSpecifiedVal := "Not specified"
			if Colors {
				notSpecifiedVal = fmt.Sprintf("[gray]%s[c]", notSpecifiedVal)
			}

			dnsZoneProps.SetCell(idx, 2, tview.NewTableCell(notSpecifiedVal))
		}
		idx += 1
	}
}

type recordRef struct {
	nodeDN string
	idx    int
}

func reloadADIDNSZone(currentNode *tview.TreeNode) {
	objectDN := currentNode.GetReference().(string)

	updateLog("Fetching nodes for zone '"+objectDN+"'...", "yellow")

	numLoadedNodes := loadZoneNodes(currentNode)

	if numLoadedNodes >= 0 {
		updateLog(fmt.Sprintf("Loaded %d nodes (%s)", numLoadedNodes, objectDN), "green")
	}

	if len(currentNode.GetChildren()) != 0 && !currentNode.IsExpanded() {
		currentNode.SetExpanded(true)
	}
}

func reloadADIDNSNode(currentNode *tview.TreeNode) {
	objectDN := currentNode.GetReference().(string)

	node, err := lc.GetADIDNSNode(objectDN)
	nodeCache[node.DN] = node

	if err == nil {
		updateLog(fmt.Sprintf("Loaded node '%s'", node.DN), "green")
	} else {
		updateLog(fmt.Sprint(err), "red")
	}

	showDetails(node.DN)
}

func showDNSNodeDetails(node *adidns.DNSNode, targetTree *tview.TreeView) {
	rootNode := tview.NewTreeNode(node.Name)

	for idx, record := range node.Records {
		unixTimestamp := record.UnixTimestamp()
		timeObj := time.Unix(unixTimestamp, 0)

		formattedTime := fmt.Sprintf("%d", unixTimestamp)
		timeDistance := time.Since(timeObj)
		if FormatAttrs {
			if unixTimestamp != -1 {
				formattedTime = timeObj.Format(TimeFormat)
			} else {
				formattedTime = "static"
			}
		}

		if Colors {
			daysDiff := timeDistance.Hours() / 24
			color := "gray"
			if unixTimestamp != -1 {
				if daysDiff <= 7 {
					color = "green"
				} else if daysDiff <= 90 {
					color = "yellow"
				} else {
					color = "red"
				}
			}

			formattedTime = fmt.Sprintf("[%s]%s[c]", color, formattedTime)
		}

		recordName := fmt.Sprintf(
			"%s [TTL=%d] (%s)",
			record.PrintType(),
			record.TTLSeconds,
			formattedTime,
		)

		recordTreeNode := tview.NewTreeNode(recordName).
			SetReference(recordRef{node.DN, idx})

		parsedRecord := record.GetRecordData()
		recordFields := adidns.DumpRecordFields(parsedRecord)
		for idx, field := range recordFields {
			fieldName := tview.Escape(fmt.Sprintf("%s=%v", field.Name, field.Value))
			fieldTreeNode := tview.NewTreeNode(fieldName).SetReference(idx)
			recordTreeNode.AddChild(fieldTreeNode)
		}

		rootNode.AddChild(recordTreeNode)
	}

	targetTree.SetRoot(rootNode)
	go func() {
		app.Draw()
	}()
}

func showDetails(objectDN string) {
	zone, ok := zoneCache[objectDN]
	if ok {
		showZoneDetails(&zone)
	}

	node, ok := nodeCache[objectDN]
	if ok {
		parentZone, err := getParentZone(objectDN)
		if err == nil {
			dnsSidePanel.SetTitle(fmt.Sprintf("Records (%s)", parentZone.Name))
		} else {
			dnsSidePanel.SetTitle("Records")
		}
		dnsSidePanel.SwitchToPage("node-records")

		showDNSNodeDetails(&node, dnsNodeRecords)
	}
}

func loadZoneNodes(zoneNode *tview.TreeNode) int {
	zoneDN := zoneNode.GetReference().(string)
	_, isZone := zoneCache[zoneDN]
	if !isZone {
		updateLog("The selected tree node is not a DNS zone", "red")
		return -1
	}

	nodes, err := lc.GetADIDNSNodes(zoneDN)
	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		return -1
	}

	zoneNode.ClearChildren()

	nodeFilter := dnsNodeFilter.GetText()
	nodeRegexp, _ := regexp.Compile(nodeFilter)

	for _, node := range nodes {
		nodeCache[node.DN] = node

		nodeMatch := nodeRegexp.FindStringIndex(node.Name)
		if nodeMatch == nil {
			continue
		}

		nodeName := node.Name
		if Emojis {
			nodeName = "📃" + nodeName
		}

		treeNode := tview.NewTreeNode(nodeName).
			SetReference(node.DN).
			SetSelectable(true).
			SetExpanded(false)

		zoneNode.AddChild(treeNode)
	}

	return len(nodes)
}

func initADIDNSPage() {
	dnsQueryPanel = tview.NewInputField()
	dnsQueryPanel.
		SetPlaceholder("Type a DNS zone or leave it blank and hit enter to query all zones").
		SetTitle("Zone Search").
		SetBorder(true)
	assignInputFieldTheme(dnsQueryPanel)

	dnsNodeFilter = tview.NewInputField()
	dnsNodeFilter.
		SetPlaceholder("Regex for dnsNode name").
		SetTitle("dnsNode Filter").
		SetBorder(true)
	assignInputFieldTheme(dnsNodeFilter)

	dnsZoneFilter = tview.NewInputField()
	dnsZoneFilter.
		SetPlaceholder("Regex for dnsZone name").
		SetTitle("dnsZone Filter").
		SetBorder(true)
	assignInputFieldTheme(dnsZoneFilter)

	dnsZoneProps = tview.NewTable().
		SetSelectable(true, true).
		SetEvaluateAllRows(true)

	dnsNodeRecords = tview.NewTreeView()

	dnsTreePanel = tview.NewTreeView()
	dnsTreePanel.
		SetTitle("Zones & Nodes").
		SetBorder(true)

	dnsTreePanel.SetChangedFunc(func(objNode *tview.TreeNode) {
		dnsZoneProps.Clear()

		objNodeRef := objNode.GetReference()
		if objNodeRef == nil {
			return
		}

		nodeDN := objNodeRef.(string)
		showDetails(nodeDN)
	})

	dnsZoneFilter.SetChangedFunc(func(text string) {
		rebuildDnsTree(dnsTreePanel.GetRoot())
	})

	dnsNodeFilter.SetChangedFunc(func(text string) {
		rebuildDnsTree(dnsTreePanel.GetRoot())
	})

	dnsQueryPanel.SetDoneFunc(dnsQueryDoneHandler)

	dnsTreePanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		currentNode := dnsTreePanel.GetCurrentNode()
		if currentNode == nil || currentNode.GetReference() == nil {
			return event
		}

		level := currentNode.GetLevel()

		switch event.Rune() {
		case 'r', 'R':
			go app.QueueUpdateDraw(func() {
				if level == 0 {
					go queryDnsZones(dnsQueryPanel.GetText())
				} else if level == 1 {
					reloadADIDNSZone(currentNode)
				} else if level == 2 {
					reloadADIDNSNode(currentNode)
				}
			})

			return nil
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
				dnsTreePanel.SetCurrentNode(currentNode)
			} else { // Collapse parent node
				pathToCurrent := dnsTreePanel.GetPath(currentNode)
				if len(pathToCurrent) > 1 {
					parentNode := pathToCurrent[len(pathToCurrent)-2]
					parentNode.SetExpanded(false)
					dnsTreePanel.SetCurrentNode(parentNode)
				}
			}
			return nil
		case tcell.KeyDelete:
			if currentNode.GetReference() == nil {
				return nil
			}

			openDeleteObjectForm(currentNode, func() {
				if level == 1 {
					go queryDnsZones(dnsQueryPanel.GetText())
				} else if level == 2 {
					pathToCurrent := dnsTreePanel.GetPath(currentNode)
					if len(pathToCurrent) > 1 {
						parentNode := pathToCurrent[len(pathToCurrent)-2]
						reloadADIDNSZone(parentNode)
					}
				}
			})

			return nil
		case tcell.KeyCtrlS:
			unixTimestamp := time.Now().UnixMilli()
			outputFilename := fmt.Sprintf("%d_dns.json", unixTimestamp)
			exportADIDNSToFile(currentNode, outputFilename)
		case tcell.KeyCtrlN:
			if currentNode == dnsTreePanel.GetRoot() {
				openCreateZoneForm()
			} else {
				if level == 1 {
					openCreateNodeForm(currentNode)
				} else if level == 2 {
					parentZone := getParentNode(currentNode, dnsTreePanel)
					openCreateNodeForm(parentZone)
				}
			}
		case tcell.KeyCtrlE:
			if level == 1 {
				// TODO: Edit zone properties
			} else if level == 2 {
				openUpdateNodeForm(currentNode)
			}
		}

		return event
	})

	dnsNodeRecords.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		currentNode := dnsNodeRecords.GetCurrentNode()
		if currentNode == nil || currentNode.GetReference() == nil {
			return event
		}

		switch event.Key() {
		case tcell.KeyCtrlE:
			node := dnsTreePanel.GetCurrentNode()
			openUpdateNodeForm(node)
			return nil
		case tcell.KeyDelete:
			if currentNode.GetLevel() == 1 {
				openDeleteRecordForm(currentNode)
			} else if currentNode.GetLevel() == 2 {
				pathToCurrent := dnsNodeRecords.GetPath(currentNode)
				if len(pathToCurrent) > 1 {
					parentNode := pathToCurrent[len(pathToCurrent)-2]
					openDeleteRecordForm(parentNode)
				}
			}

			return nil
		}

		return event
	})

	dnsSidePanel = tview.NewPages()
	dnsSidePanel.
		AddPage("zone-props", dnsZoneProps, true, true).
		AddPage("node-records", dnsNodeRecords, true, true).
		SetBorder(true)

	dnsPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(dnsQueryPanel, 0, 2, false).
				AddItem(dnsNodeFilter, 0, 1, false).
				AddItem(dnsZoneFilter, 0, 1, false),
			3, 0, false,
		).
		AddItem(
			tview.NewFlex().
				AddItem(dnsTreePanel, 0, 1, false).
				AddItem(dnsSidePanel, 0, 1, false),
			0, 8, false,
		)

	dnsPage.SetInputCapture(dnsPageKeyHandler)
}

func dnsPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		dnsRotateFocus()
		return nil
	}

	return event
}

func rebuildDnsTree(rootNode *tview.TreeNode) int {
	if rootNode == nil {
		return 0
	}

	expandedZones := make(map[string]bool)
	childrenZones := rootNode.GetChildren()
	for _, child := range childrenZones {
		ref, ok := child.GetReference().(string)
		if ok && child.IsExpanded() {
			expandedZones[ref] = true
		}
	}
	rootNode.ClearChildren()

	zoneFilter := dnsZoneFilter.GetText()
	zoneRegexp, err := regexp.Compile(zoneFilter)
	if err != nil {
		updateLog("Invalid zone filter '"+zoneFilter+"' specified", "red")
		return -1
	}

	totalNodes := 0
	for _, zone := range domainZones {
		zoneCache[zone.DN] = zone
		zoneMatch := zoneRegexp.FindStringIndex(zone.Name)

		if zoneMatch == nil {
			continue
		}

		zoneNodeName := zone.Name
		if Emojis {
			zoneNodeName = "🌐" + zoneNodeName
		}

		childNode := tview.NewTreeNode(zoneNodeName).
			SetReference(zone.DN).
			SetExpanded(expandedZones[zone.DN]).
			SetSelectable(true)

		totalNodes += loadZoneNodes(childNode)
		rootNode.AddChild(childNode)
	}

	for _, zone := range forestZones {
		zoneCache[zone.DN] = zone
		zoneMatch := zoneRegexp.FindStringIndex(zone.Name)

		if zoneMatch == nil {
			continue
		}

		zoneNodeName := zone.Name
		if Emojis {
			zoneNodeName = "🌲" + zoneNodeName
		}

		childNode := tview.NewTreeNode(zoneNodeName).
			SetReference(zone.DN).
			SetExpanded(expandedZones[zone.DN]).
			SetSelectable(true)

		totalNodes += loadZoneNodes(childNode)
		rootNode.AddChild(childNode)
	}

	go func() {
		app.Draw()
	}()
	return totalNodes
}

func queryDnsZones(targetZone string) {
	dnsRunControl.Lock()
	if dnsRunning {
		dnsRunControl.Unlock()
		updateLog("Another query is still running...", "yellow")
		return
	}
	dnsRunning = true
	dnsRunControl.Unlock()

	clear(nodeCache)
	clear(zoneCache)
	clear(domainZones)
	clear(forestZones)

	app.QueueUpdateDraw(func() {
		updateLog("Querying ADIDNS zones...", "yellow")

		domainZones, _ = lc.GetADIDNSZones(targetZone, false)
		forestZones, _ = lc.GetADIDNSZones(targetZone, true)

		totalZones := len(domainZones) + len(forestZones)
		if totalZones == 0 {
			updateLog("No ADIDNS zones found", "red")
			rootNode.ClearChildren()

			dnsRunControl.Lock()
			dnsRunning = false
			dnsRunControl.Unlock()
			return
		}

		// Setting up root node
		rootNode := tview.NewTreeNode(lc.RootDN).
			SetReference(lc.RootDN).
			SetSelectable(true)
		dnsTreePanel.
			SetRoot(rootNode).
			SetCurrentNode(rootNode)

		totalNodes := rebuildDnsTree(rootNode)

		updateLog(fmt.Sprintf("Found %d ADIDNS zones and %d nodes", totalZones, totalNodes), "green")
		app.SetFocus(dnsTreePanel)
	})

	dnsRunControl.Lock()
	dnsRunning = false
	dnsRunControl.Unlock()
}

func dnsQueryDoneHandler(key tcell.Key) {
	go queryDnsZones(dnsQueryPanel.GetText())
}

func dnsRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case dnsTreePanel:
		app.SetFocus(dnsQueryPanel)
	case dnsQueryPanel:
		app.SetFocus(dnsNodeFilter)
	case dnsNodeFilter:
		app.SetFocus(dnsZoneFilter)
	case dnsZoneFilter:
		app.SetFocus(dnsZoneProps)
	case dnsZoneProps:
		app.SetFocus(dnsTreePanel)
	}
}
