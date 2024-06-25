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

var recordCache = make(map[string][]adidns.RecordContainer, 0)

func getParentZone(objectDN string) (adidns.DNSZone, error) {
	objectDNParts := strings.Split(objectDN, ",")

	if len(objectDNParts) > 1 {
		parentZoneDN := strings.Join(objectDNParts[1:], ",")
		parentZone, zoneOk := zoneCache[parentZoneDN]
		if zoneOk {
			return parentZone, nil
		} else {
			return adidns.DNSZone{}, fmt.Errorf("Parent zone not found in the cache")
		}
	}

	return adidns.DNSZone{}, fmt.Errorf("Object DN too small to contain a parent zone")
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
					zoneProps[propName] = prop.Data
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
				records, _ := recordCache[objectDN]

				recordsObj := make([]any, 0)
				for idx, rec := range records {
					recordType := node.Records[idx].PrintType()
					recordsObj = append(recordsObj, map[string]any{
						"Type":     recordType,
						"Name":     rec.Name,
						"Contents": rec.Contents,
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
						exportMap[parentZone.DN] = map[string]any{
							"Zone":  parentZone,
							"Nodes": nodesMap,
						}
					}

					parentZone := (exportMap[parentZone.DN]).(map[string]any)
					parentZoneNodes := parentZone["Nodes"].(map[string]any)
					parentZoneNodes[node.DN] = recordsObj
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

func showZoneOrNodeDetails(objectDN string) {
	zone, ok := zoneCache[objectDN]
	if ok {
		dnsSidePanel.SetTitle("dnsZone Properties")
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
					mappedPropStr = mappedProp.Format(TimeFormat)
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

		return
	}

	node, ok := nodeCache[objectDN]
	if ok {
		parsedRecords, _ := recordCache[objectDN]
		parentZone, err := getParentZone(objectDN)
		if err == nil {
			dnsSidePanel.SetTitle(fmt.Sprintf("dnsNode Records (%s)", parentZone.Name))
		} else {
			dnsSidePanel.SetTitle("dnsNode Records")
		}

		dnsSidePanel.SwitchToPage("node-records")

		rootNode := tview.NewTreeNode(node.Name)
		dnsNodeRecords.SetRoot(rootNode)

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

			nodeName := fmt.Sprintf(
				"%s [TTL=%d] (%s)",
				record.PrintType(),
				record.TTLSeconds,
				formattedTime,
			)

			recordTreeNode := tview.NewTreeNode(nodeName).
				SetSelectable(true)

			parsedRecord := parsedRecords[idx]
			recordFields := parsedRecord.DumpFields()
			for _, field := range recordFields {
				fieldName := tview.Escape(fmt.Sprintf("%s=%v", field.Name, field.Value))
				fieldTreeNode := tview.NewTreeNode(fieldName)
				recordTreeNode.AddChild(fieldTreeNode)
			}

			rootNode.AddChild(recordTreeNode)
		}
	}
}

func storeNodeRecords(node adidns.DNSNode) {
	records := make([]adidns.RecordContainer, 0)
	var fRec adidns.FriendlyRecord

	for _, record := range node.Records {
		switch record.Type {
		case 0x0000:
			fRec = new(adidns.ZERORecord)
		case 0x0001:
			fRec = new(adidns.ARecord)
		case 0x0002:
			fRec = new(adidns.NSRecord)
		case 0x0003:
			fRec = new(adidns.MDRecord)
		case 0x0004:
			fRec = new(adidns.MFRecord)
		case 0x0005:
			fRec = new(adidns.CNAMERecord)
		case 0x0006:
			fRec = new(adidns.SOARecord)
		case 0x0007:
			fRec = new(adidns.MBRecord)
		case 0x0008:
			fRec = new(adidns.MGRecord)
		case 0x0009:
			fRec = new(adidns.MRRecord)
		case 0x000A:
			fRec = new(adidns.NULLRecord)
		case 0x000B:
			fRec = new(adidns.WKSRecord)
		case 0x000C:
			fRec = new(adidns.PTRRecord)
		case 0x000D:
			fRec = new(adidns.HINFORecord)
		case 0x000E:
			fRec = new(adidns.MINFORecord)
		case 0x000F:
			fRec = new(adidns.MXRecord)
		case 0x0010:
			fRec = new(adidns.TXTRecord)
		case 0x0011:
			fRec = new(adidns.RPRecord)
		case 0x0012:
			fRec = new(adidns.AFSDBRecord)
		case 0x0013:
			fRec = new(adidns.X25Record)
		case 0x0014:
			fRec = new(adidns.ISDNRecord)
		case 0x0015:
			fRec = new(adidns.RTRecord)
		case 0x0018:
			fRec = new(adidns.SIGRecord)
		case 0x0019:
			fRec = new(adidns.KEYRecord)
		case 0x001C:
			fRec = new(adidns.AAAARecord)
		case 0x001D:
			fRec = new(adidns.LOCRecord)
		case 0x001E:
			fRec = new(adidns.NXTRecord)
		case 0x0021:
			fRec = new(adidns.SRVRecord)
		case 0x0022:
			fRec = new(adidns.ATMARecord)
		case 0x0023:
			fRec = new(adidns.NAPTRRecord)
		case 0x0027:
			fRec = new(adidns.DNAMERecord)
		case 0x002B:
			fRec = new(adidns.DSRecord)
		case 0x002E:
			fRec = new(adidns.RRSIGRecord)
		case 0x002F:
			fRec = new(adidns.NSECRecord)
		case 0x0030:
			fRec = new(adidns.DNSKEYRecord)
		case 0x0031:
			fRec = new(adidns.DHCIDRecord)
		case 0x0032:
			fRec = new(adidns.NSEC3Record)
		case 0x0033:
			fRec = new(adidns.NSEC3PARAMRecord)
		case 0x0034:
			fRec = new(adidns.TLSARecord)
		case 0xFF01:
			fRec = new(adidns.WINSRecord)
		case 0xFF02:
			fRec = new(adidns.WINSRRecord)
		default:
			continue
		}

		fRec.Parse(record.Data)

		container := adidns.RecordContainer{
			node.Name,
			fRec,
		}

		records = append(records, container)
	}

	recordCache[node.DN] = records
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
	nodeRegexp, err := regexp.Compile(nodeFilter)

	for _, node := range nodes {
		nodeMatch := nodeRegexp.FindStringIndex(node.Name)
		if nodeMatch == nil {
			continue
		}

		nodeCache[node.DN] = node

		nodeName := node.Name
		if Emojis {
			nodeName = "📃" + nodeName
		}

		treeNode := tview.NewTreeNode(nodeName).
			SetReference(node.DN).
			SetSelectable(true).
			SetExpanded(false)

		zoneNode.AddChild(treeNode)
		storeNodeRecords(node)
	}

	return len(nodes)
}

func initADIDNSPage() {
	dnsQueryPanel = tview.NewInputField()
	dnsQueryPanel.
		SetPlaceholder("Type a DNS zone or leave it blank and hit enter to query all zones").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("Zone Search").
		SetBorder(true)

	dnsNodeFilter = tview.NewInputField()
	dnsNodeFilter.
		SetPlaceholder("Regex for dnsNode name").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("dnsNode Filter").
		SetBorder(true)

	dnsZoneFilter = tview.NewInputField()
	dnsZoneFilter.
		SetPlaceholder("Regex for dnsZone name").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetTitle("dnsZone Filter").
		SetBorder(true)

	dnsZoneProps = tview.NewTable().
		SetSelectable(true, true).
		SetEvaluateAllRows(true)

	dnsNodeRecords = tview.NewTreeView()

	dnsTreePanel = tview.NewTreeView()
	dnsTreePanel.
		SetTitle("Search Results").
		SetBorder(true)

	dnsTreePanel.SetChangedFunc(func(objNode *tview.TreeNode) {
		dnsZoneProps.Clear()

		objNodeRef := objNode.GetReference()
		if objNodeRef == nil {
			return
		}

		nodeDN := objNodeRef.(string)
		showZoneOrNodeDetails(nodeDN)
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

		objectDN := currentNode.GetReference().(string)

		switch event.Rune() {
		case 'r', 'R':
			if currentNode == dnsTreePanel.GetRoot() {
				return nil
			}

			go func() {
				level := currentNode.GetLevel()
				if level == 1 {
					updateLog("Fetching nodes for zone '"+objectDN+"'...", "yellow")

					numLoadedNodes := loadZoneNodes(currentNode)

					if numLoadedNodes >= 0 {
						updateLog(fmt.Sprintf("Loaded %d nodes (%s)", numLoadedNodes, objectDN), "green")
					}

					if len(currentNode.GetChildren()) != 0 && !currentNode.IsExpanded() {
						currentNode.SetExpanded(true)
					}
				} else if level == 2 {
					node, err := lc.GetADIDNSNode(objectDN)

					if err == nil {
						updateLog(fmt.Sprintf("Loaded node '%s'", node.DN), "green")
					} else {
						updateLog(fmt.Sprint(err), "red")
					}

					storeNodeRecords(node)
					showZoneOrNodeDetails(node.DN)
				}

				app.Draw()
			}()

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
			if currentNode.GetReference() != nil {
				openDeleteObjectForm(currentNode, nil)
			}
		case tcell.KeyCtrlS:
			unixTimestamp := time.Now().UnixMilli()
			outputFilename := fmt.Sprintf("%d_dns.json", unixTimestamp)
			exportADIDNSToFile(currentNode, outputFilename)
		case tcell.KeyCtrlN:
			/*
				TODO: Create zones or nodes
			*/
		case tcell.KeyCtrlE:
			/*
				TODO: Edit node records or zone properties
			*/
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

func dnsQueryDoneHandler(key tcell.Key) {
	clear(nodeCache)
	clear(zoneCache)
	clear(domainZones)
	clear(forestZones)
	clear(recordCache)

	go func() {
		dnsRunControl.Lock()
		if dnsRunning {
			dnsRunControl.Unlock()
			updateLog("Another query is still running...", "yellow")
			return
		}
		dnsRunning = true
		dnsRunControl.Unlock()

		updateLog("Querying ADIDNS zones...", "yellow")

		targetZone := dnsQueryPanel.GetText()

		domainZones, _ = lc.GetADIDNSZones(targetZone, false)
		forestZones, _ = lc.GetADIDNSZones(targetZone, true)

		totalZones := len(domainZones) + len(forestZones)
		if totalZones == 0 {
			updateLog("No ADIDNS zones found", "red")
			rootNode.ClearChildren()
			app.Draw()

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

		app.Draw()

		dnsRunControl.Lock()
		dnsRunning = false
		dnsRunControl.Unlock()
	}()
}

func dnsRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case dnsTreePanel:
		app.SetFocus(dnsQueryPanel)
	case dnsQueryPanel:
		app.SetFocus(dnsZoneProps)
	case dnsZoneProps:
		app.SetFocus(dnsTreePanel)
	}
}
