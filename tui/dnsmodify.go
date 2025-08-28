package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Macmod/godap/v2/pkg/adidns"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var supportedRecordTypes []string = []string{
	"A", "AAAA", "CNAME", "TXT", "NS", "SOA", "SRV", "MX", "PTR",
	"MD", "MF", "MB", "MG", "MR", "DNAME",
	"HINFO", "ISDN", "X25", "LOC", "AFSDB", "RT",
}

func addZoneHandler(zoneForm *XForm, currentFocus tview.Primitive) func() {
	return func() {
		zoneName := zoneForm.GetFormItemByLabel("Zone Name").(*tview.InputField).GetText()
		zoneAllowUpdate, _ := zoneForm.GetFormItemByLabel("Updates").(*tview.DropDown).GetCurrentOption()
		zoneContainer, _ := zoneForm.GetFormItemByLabel("Container").(*tview.DropDown).GetCurrentOption()
		zoneNS := zoneForm.GetFormItemByLabel("NameServer").(*tview.InputField).GetText()
		zoneEmail := zoneForm.GetFormItemByLabel("AdminEmail").(*tview.InputField).GetText()

		propType := adidns.MakeProp(0x1, []byte{1, 0, 0, 0})
		propAllowUpdate := adidns.MakeProp(0x2, []byte{byte(zoneAllowUpdate)})
		propNoRefresh := adidns.MakeProp(0x10, []byte{168})
		propRefresh := adidns.MakeProp(0x20, []byte{168})
		propAging := adidns.MakeProp(0x40, []byte{0})
		propScavDa := adidns.MakeProp(0x90, []byte{})
		propAutoNsDa := adidns.MakeProp(0x92, []byte{})

		defaultProps := []adidns.DNSProperty{
			propType,
			propAllowUpdate,
			propNoRefresh,
			propRefresh,
			propAging,
			propScavDa,
			propAutoNsDa,
		}

		isForest := zoneContainer == 1
		zoneDN, err := lc.AddADIDNSZone(zoneName, defaultProps, isForest)

		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			return
		}

		// Basic records required so that
		// the DNS will synchronize the zone from
		// Active Directory
		recSOA := adidns.MakeDNSRecord(
			&adidns.SOARecord{Serial: 1, Refresh: 900, Retry: 600, Expire: 86400, MinimumTTL: 3600, NamePrimaryServer: zoneNS, ZoneAdminEmail: zoneEmail},
			0x06,
			3600,
		)

		recNS := adidns.MakeDNSRecord(&adidns.NSRecord{NameNode: zoneNS}, 0x02, 3600)

		defaultRecords := []adidns.DNSRecord{
			recSOA,
			recNS,
		}

		_, err = lc.AddADIDNSNode("@", zoneDN, defaultRecords)
		if err == nil {
			updateLog(fmt.Sprintf("Zone '%s' created successfully!", zoneName), "green")
		} else {
			updateLog(fmt.Sprintf("Zone '%s' created without SOA & NS records - a problem might have occurred.", zoneName), "yellow")
		}

		go queryDnsZones(dnsQueryPanel.GetText())
		app.SetRoot(appPanel, true).SetFocus(currentFocus)
	}
}

func openCreateZoneForm() {
	currentFocus := app.GetFocus()

	zoneForm := NewXForm().
		AddInputField("Zone Name", "", 0, nil, nil).
		AddDropDown("Container", []string{"DomainDnsZones", "ForestDnsZones"}, 0, nil).
		AddDropDown("Updates", []string{"None", "Nonsecure and secure", "Secure only"}, 0, nil).
		AddInputField("NameServer", "", 0, nil, nil).
		AddInputField("AdminEmail", "", 0, nil, nil)

	zoneNameFormItem := zoneForm.GetFormItemByLabel("Zone Name").(*tview.InputField)
	zoneNameFormItem.SetPlaceholder("example.com")
	assignInputFieldTheme(zoneNameFormItem)

	zoneForm.SetInputCapture(handleEscape(dnsTreePanel))

	zoneForm.
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		}).
		AddButton("Add", addZoneHandler(zoneForm, currentFocus))

	zoneForm.SetTitle("Create ADIDNS Zone").SetBorder(true)
	app.SetRoot(zoneForm, true).SetFocus(zoneForm)
}

func openActionNodeForm(target *tview.TreeNode, update bool) {
	currentFocus := app.GetFocus()

	targetDN := target.GetReference().(string)
	targetDNParts := strings.Split(targetDN, ",")
	firstDNComponents := strings.Split(targetDNParts[0], "=")
	firstDNValue := firstDNComponents[1]

	var (
		title string
	)

	if update {
		title = "Update"
	} else {
		title = "Create"
	}

	// Left panels
	nodeInfoPanel := NewXForm()
	nodeInfoPanel.SetTitle("Node")
	nodeInfoPanel.SetBorder(true)

	recordValuePages := tview.NewPages()

	// Right panels
	recordsPreview := tview.NewTreeView()
	recordsPreview.
		SetRoot(tview.NewTreeNode("")).
		SetTitle("Records Preview").
		SetBorder(true)

	nodeNameInput := tview.NewInputField().
		SetLabel("Node Name").
		SetChangedFunc(func(text string) {
			root := recordsPreview.GetRoot()
			if root != nil {
				root.SetText(text)
			}
		})
	nodeNameInput.SetPlaceholder("The node name is usually the subdomain you want to create")
	assignInputFieldTheme(nodeNameInput)

	// Preview area internal structure
	var stagedParsedRecords []adidns.RecordData
	var stagedRecords []adidns.DNSRecord

	if update {
		// Prefill the existing records
		// of the node into the staging area
		node, ok := nodeCache[targetDN]
		if !ok {
			return
		}
		existingRecords := node.Records

		stagedParsedRecords = make([]adidns.RecordData, len(existingRecords))
		stagedRecords = make([]adidns.DNSRecord, len(existingRecords))

		copy(stagedRecords, existingRecords)

		for idx, record := range existingRecords {
			parsedRecord := record.GetRecordData()
			stagedParsedRecords[idx] = parsedRecord
		}

		// Show the existing records in the preview
		showDNSNodeDetails(&node, recordsPreview)
	} else {
		// Set up an empty staging area
		stagedParsedRecords = make([]adidns.RecordData, 0)
		stagedRecords = make([]adidns.DNSRecord, 0)
	}

	recordsPreview.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyDelete:
			currentNode := recordsPreview.GetCurrentNode()
			if currentNode == nil {
				return nil
			}

			level := currentNode.GetLevel()

			var nodeToDelete *tview.TreeNode

			if level == 1 {
				nodeToDelete = currentNode
			} else if level == 2 {
				pathToCurrent := recordsPreview.GetPath(currentNode)
				if len(pathToCurrent) > 1 {
					nodeToDelete = pathToCurrent[len(pathToCurrent)-2]
				}
			}

			if nodeToDelete != nil {
				recIdx := -1
				siblings := recordsPreview.GetRoot().GetChildren()
				for idx, node := range siblings {
					if node == nodeToDelete {
						recIdx = idx
					}
				}

				if recIdx != -1 {
					stagedParsedRecords = append(stagedParsedRecords[:recIdx], stagedParsedRecords[recIdx+1:]...)
					stagedRecords = append(stagedRecords[:recIdx], stagedRecords[recIdx+1:]...)

					recordsPreview.GetRoot().RemoveChild(nodeToDelete)
				}

				go func() {
					app.Draw()
				}()
			}

			return nil
		}

		return event
	})

	// nodeInfoPanel setup
	parentZone, err := getParentZone(targetDN)
	if err == nil {
		nodeInfoPanel.AddTextView("Zone DN", parentZone.DN, 0, 1, false, true)
	}
	if update {
		nodeInfoPanel.AddTextView("Node Name", firstDNValue, 0, 1, false, true)
	}

	// recordContent setup
	recordTypeInput := tview.NewDropDown().
		SetLabel("Record Type").
		SetOptions(supportedRecordTypes, func(text string, index int) {
			switch text {
			case "HINFO", "ISDN", "TXT", "X25", "LOC":
				recordValuePages.SwitchToPage("multiple")
			case "MX", "AFSDB", "RT":
				recordValuePages.SwitchToPage("namepref")
			case "SRV":
				recordValuePages.SwitchToPage("srv")
			case "SOA":
				recordValuePages.SwitchToPage("soa")
			default:
				recordValuePages.SwitchToPage("default")
			}
		})
	assignDropDownTheme(recordTypeInput)

	recordTypeInput.
		SetCurrentOption(0).
		SetLabelWidth(12).
		SetBorderPadding(1, 0, 1, 1)

	recordTTLInput := tview.NewInputField().SetText("3600")
	recordTTLInput.
		SetLabel("Record TTL").
		SetLabelWidth(12).
		SetBorderPadding(1, 0, 1, 1)
	assignInputFieldTheme(recordTTLInput)

	nameprefRecordValueInput := NewXForm().
		AddInputField("Preference", "", 0, numericAcceptanceFunc, nil).
		AddInputField("Exchange", "", 0, nil, nil)

	soaRecordValueInput := NewXForm().
		AddInputField("Serial", "", 0, numericAcceptanceFunc, nil).
		AddInputField("Refresh", "", 0, numericAcceptanceFunc, nil).
		AddInputField("Retry", "", 0, numericAcceptanceFunc, nil).
		AddInputField("Expire", "", 0, numericAcceptanceFunc, nil).
		AddInputField("MinimumTTL", "", 0, numericAcceptanceFunc, nil).
		AddInputField("NamePrimaryServer", "", 0, nil, nil).
		AddInputField("ZoneAdminEmail", "", 0, nil, nil)

	srvRecordValueInput := NewXForm().
		AddInputField("Priority", "", 0, numericAcceptanceFunc, nil).
		AddInputField("Weight", "", 0, numericAcceptanceFunc, nil).
		AddInputField("Port", "", 0, numericAcceptanceFunc, nil).
		AddInputField("NameTarget", "", 0, nil, nil)

	defaultRecordValueInput := NewXForm().
		AddInputField("Record Value", "", 0, nil, nil)
	defaultRecordValueInput.GetFormItem(0).(*tview.InputField).SetPlaceholder("Type the record value and add it to the preview")

	multipleRecordValueInput := NewXForm().
		AddTextArea("Record Values", "", 0, 0, 0, nil)
	multipleRecordValueInput.GetFormItem(0).(*tview.TextArea).SetPlaceholder("Type in the values for the record line-by-line\nand add it to the preview")

	cancelBtn := tview.NewButton("Go Back").SetSelectedFunc(func() {
		app.SetRoot(appPanel, true).SetFocus(currentFocus)
	})
	assignButtonTheme(cancelBtn)

	updateBtn := tview.NewButton(title).SetSelectedFunc(func() {
		var nodeDN string
		var action string
		var err error
		if !update {
			nodeName := nodeNameInput.GetText()
			nodeDN, err = lc.AddADIDNSNode(
				nodeName,
				targetDN,
				stagedRecords,
			)
			action = "created"
		} else {
			nodeDN = targetDN
			err = lc.ReplaceADIDNSRecords(
				nodeDN,
				stagedRecords,
			)
			action = "updated"
		}

		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			return
		}

		go app.QueueUpdateDraw(func() {
			if !update {
				reloadADIDNSZone(target)
			} else {
				reloadADIDNSNode(target)
			}
		})

		updateLog(fmt.Sprintf("Node '%s' %s successfully", nodeDN, action), "green")
		app.SetRoot(appPanel, true).SetFocus(currentFocus)
	})
	assignButtonTheme(updateBtn)

	addToPreview := tview.NewButton("Add To Preview").SetSelectedFunc(func() {
		_, recordTypeVal := recordTypeInput.GetCurrentOption()
		recordTTLVal := recordTTLInput.GetText()
		recordTTLInt, err := strconv.Atoi(recordTTLVal)

		if err != nil {
			return
		}

		// Append the new record to the preview area
		var recordValue any

		switch recordTypeVal {
		case "HINFO", "ISDN", "TXT", "X25", "LOC":
			recordValue = strings.Split(multipleRecordValueInput.GetFormItem(0).(*tview.TextArea).GetText(), "\n")
		case "MX", "AFSDB", "RT":
			recordValue = map[string]string{
				"Preference": nameprefRecordValueInput.GetFormItemByLabel("Preference").(*tview.InputField).GetText(),
				"Exchange":   nameprefRecordValueInput.GetFormItemByLabel("Exchange").(*tview.InputField).GetText(),
			}
		case "SOA":
			recordValue = map[string]string{
				"Serial":            soaRecordValueInput.GetFormItemByLabel("Serial").(*tview.InputField).GetText(),
				"Refresh":           soaRecordValueInput.GetFormItemByLabel("Refresh").(*tview.InputField).GetText(),
				"Retry":             soaRecordValueInput.GetFormItemByLabel("Retry").(*tview.InputField).GetText(),
				"Expire":            soaRecordValueInput.GetFormItemByLabel("Expire").(*tview.InputField).GetText(),
				"MinimumTTL":        soaRecordValueInput.GetFormItemByLabel("MinimumTTL").(*tview.InputField).GetText(),
				"NamePrimaryServer": soaRecordValueInput.GetFormItemByLabel("NamePrimaryServer").(*tview.InputField).GetText(),
				"ZoneAdminEmail":    soaRecordValueInput.GetFormItemByLabel("ZoneAdminEmail").(*tview.InputField).GetText(),
			}
		case "SRV":
			recordValue = map[string]string{
				"Priority":   srvRecordValueInput.GetFormItemByLabel("Priority").(*tview.InputField).GetText(),
				"Weight":     srvRecordValueInput.GetFormItemByLabel("Weight").(*tview.InputField).GetText(),
				"Port":       srvRecordValueInput.GetFormItemByLabel("Port").(*tview.InputField).GetText(),
				"NameTarget": srvRecordValueInput.GetFormItemByLabel("NameTarget").(*tview.InputField).GetText(),
			}
		default:
			recordValue = defaultRecordValueInput.GetFormItem(0).(*tview.InputField).GetText()
		}

		record := adidns.RecordFromInput(recordTypeVal, recordValue)
		stagedParsedRecords = append(stagedParsedRecords, record)

		recordTypeInt := adidns.FindRecordType(recordTypeVal)
		recordToStore := adidns.MakeDNSRecord(record, recordTypeInt, uint32(recordTTLInt))
		stagedRecords = append(stagedRecords, recordToStore)

		// Make a new node to add to the preview
		var newNode adidns.DNSNode
		if update {
			node, ok := nodeCache[targetDN]
			if !ok {
				return
			}
			newNode = adidns.DNSNode{DN: targetDN, Name: node.Name, Records: stagedRecords}
		} else {
			nodeName := nodeNameInput.GetText()
			newNode = adidns.DNSNode{DN: "<NodeDN>", Name: nodeName, Records: stagedRecords}
		}

		// Show preview
		showDNSNodeDetails(&newNode, recordsPreview)
	})
	assignButtonTheme(addToPreview)

	// Page setup
	actionNodePanel := tview.NewFlex()
	actionNodePanel.
		SetInputCapture(handleEscape(dnsTreePanel)).
		SetTitle(fmt.Sprintf("%s ADIDNS Node", title)).
		SetBorder(true)

	actionNodePanel.SetDirection(tview.FlexRow)

	recordValuePages.AddPage("default", defaultRecordValueInput, true, true)
	recordValuePages.AddPage("multiple", multipleRecordValueInput, true, false)
	recordValuePages.AddPage("namepref", nameprefRecordValueInput, true, false)
	recordValuePages.AddPage("soa", soaRecordValueInput, true, false)
	recordValuePages.AddPage("srv", srvRecordValueInput, true, false)

	recordContentPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(recordTypeInput, 2, 0, false).
		AddItem(recordTTLInput, 2, 0, false).
		AddItem(recordValuePages, 0, 1, false).
		AddItem(addToPreview, 1, 0, false)

	recordContentPanel.
		SetTitle("Record Contents").
		SetBorder(true)

	leftPanel := tview.NewFlex().SetDirection(tview.FlexRow)

	// If it's node creation,
	// show an input to specify the node name.
	// Otherwise just keep it hidden.
	if !update {
		nodeInfoPanel.AddFormItem(nodeNameInput)
	}

	actionNodePanel.AddItem(
		tview.NewFlex().
			AddItem(
				leftPanel.
					AddItem(nodeInfoPanel, 7, 0, false).
					AddItem(recordContentPanel, 0, 1, false),
				0, 1, false).
			AddItem(recordsPreview, 0, 1, false),
		0, 1, false).
		AddItem(
			tview.NewFlex().
				AddItem(tview.NewBox(), 1, 0, false). // Spacing
				AddItem(cancelBtn, 10, 0, false).
				AddItem(tview.NewBox(), 0, 1, false). // Spacing
				AddItem(updateBtn, 10, 0, false).
				AddItem(tview.NewBox(), 1, 0, false), // Spacing
			1, 0, false)

	app.SetRoot(actionNodePanel, true).SetFocus(actionNodePanel)
}

func openUpdateNodeForm(node *tview.TreeNode) {
	openActionNodeForm(node, true)
}

func openCreateNodeForm(zone *tview.TreeNode) {
	openActionNodeForm(zone, false)
}

func openDeleteRecordForm(record *tview.TreeNode) {
	currentFocus := app.GetFocus()
	recRef := record.GetReference().(recordRef)

	nodeDN := recRef.nodeDN
	recIdx := recRef.idx

	node, ok := nodeCache[nodeDN]
	if !ok {
		return
	}
	records := node.Records

	confirmText := fmt.Sprintf("Do you really want to delete this record?\nRecordIdx: %d\nNode: %s", recIdx, nodeDN)
	promptModal := tview.NewModal().
		SetText(confirmText).
		AddButtons([]string{"No", "Yes"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				// TODO: Add safety check for changes outside Godap
				updateRecords := append(records[:recIdx], records[recIdx+1:]...)

				err = lc.ReplaceADIDNSRecords(nodeDN, updateRecords)
				if err != nil {
					updateLog(fmt.Sprint(err), "red")
					app.SetRoot(appPanel, true).SetFocus(currentFocus)
					return
				}

				node := dnsTreePanel.GetCurrentNode()
				reloadADIDNSNode(node)

				updateLog("Record deleted successfully", "green")
				app.SetRoot(appPanel, true).SetFocus(currentFocus)
			} else {
				app.SetRoot(appPanel, true).SetFocus(currentFocus)
			}
		})

	app.SetRoot(promptModal, true).SetFocus(promptModal)
}

/*
Records can also be added instead of replaced with:

```
	rec := recordFromInput(recordType, recordValue)

	recordsToAdd := []adidns.DNSRecord{
		adidns.MakeDNSRecord(
			rec,
			adidns.FindRecordType(recordType),
			uint32(recordTTLInt)),
	}

	err = lc.AddADIDNSRecords(nodeDN, recordsToAdd)
	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		app.SetRoot(appPanel, true).SetFocus(currentFocus)
		return
	}

	reloadADIDNSNode(node)
````
*/
