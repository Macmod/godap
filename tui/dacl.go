package tui

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/Macmod/godap/v2/pkg/sdl"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	runControlDacl sync.Mutex
	runningDacl    bool

	sd         *sdl.SecurityDescriptor
	parsedAces []ParsedACE
)

func parseAces(dst *[]ParsedACE, srcSD *sdl.SecurityDescriptor) {
	var samAccountName string
	var sidMap map[string]string = make(map[string]string)
	var ok bool

	for idx, ace := range srcSD.DACL.Aces {
		entry := ParsedACE{
			Idx:            idx,
			SamAccountName: "",
			Type:           "",
			Inheritance:    false,
			Scope:          "This object only",
			NoPropagate:    false,
			Severity:       0,
			Raw:            ace,
		}

		var ACEFlags int
		switch aceVal := ace.(type) {
		case *sdl.BASIC_ACE:
			sid := ldaputils.ConvertSID(aceVal.SID)

			if aceVal.Header.ACEType == "00" {
				entry.Type = "Allow"
			} else {
				entry.Type = "Deny"
			}

			samAccountName, ok = sidMap[sid]
			if !ok {
				samAccountName, err = lc.FindSamForSID(sid)
				if err == nil {
					sidMap[sid] = samAccountName
					entry.SamAccountName = samAccountName
				} else {
					entry.SamAccountName = sid
				}
			} else {
				entry.SamAccountName = samAccountName
			}

			ACEFlags = ldaputils.HexToInt(aceVal.Header.ACEFlags)
			if ACEFlags&sdl.AceFlagsMap["INHERITED_ACE"] != 0 {
				entry.Inheritance = true
			}

			if ACEFlags&sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"] != 0 {
				entry.NoPropagate = true
			}

			permissions := ldaputils.HexToInt(ldaputils.EndianConvert(aceVal.Mask))

			entry.Mask, entry.Severity = sdl.AceMaskToText(permissions, "")
		case *sdl.OBJECT_ACE:
			sid := ldaputils.ConvertSID(aceVal.SID)

			if aceVal.Header.ACEType == "05" {
				entry.Type = "Allow"
			} else {
				entry.Type = "Deny"
			}
			samAccountName, ok = sidMap[sid]
			if !ok {
				samAccountName, err = lc.FindSamForSID(sid)
				if err == nil {
					sidMap[sid] = samAccountName
					entry.SamAccountName = samAccountName
				} else {
					entry.SamAccountName = sid
				}
			} else {
				entry.SamAccountName = samAccountName
			}

			ACEFlags = ldaputils.HexToInt(aceVal.Header.ACEFlags)
			if ACEFlags&sdl.AceFlagsMap["INHERITED_ACE"] != 0 {
				entry.Inheritance = true
			}

			if ACEFlags&sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"] != 0 {
				entry.NoPropagate = true
			}

			permissions := ldaputils.HexToInt(ldaputils.EndianConvert(aceVal.Mask))
			objectType, inheritedObjectType := aceVal.GetObjectAndInheritedType()
			entry.Mask, entry.Severity = sdl.AceMaskToText(permissions, objectType)
			entry.Scope = sdl.AceFlagsToText(aceVal.Header.ACEFlags, inheritedObjectType)
		case *sdl.NOTIMPL_ACE:
			// Should not happen under normal circumstances
			entry.Type = "NOTIMPL"
		}

		*dst = append(*dst, entry)
	}
}

var (
	object string

	daclPage             *tview.Flex
	objectNameInputDacl  *tview.InputField
	daclEntriesPanel     *tview.Table
	acePanel             *tview.List
	daclOwnerTextView    *tview.TextView
	controlFlagsTextView *tview.TextView
	aceMask              *tview.TextView
	aceMaskBinary        *tview.TextView
	ownerPrincipal       string
	groupPrincipal       string
)

func queryDacl(target string) {
	updateLog("Fetching DACL for '"+target+"'", "yellow")
	go app.QueueUpdateDraw(updateDaclEntries)
}

func initDaclPage(includeCurSchema bool) {
	loadRightVars()
	loadSchemaVars(includeCurSchema)

	objectNameInputDacl = tview.NewInputField()
	objectNameInputDacl.
		SetPlaceholder("Type an object's sAMAccountName or DN").
		SetTitle("Object").
		SetBorder(true)
	assignInputFieldTheme(objectNameInputDacl)

	acePanel = tview.NewList()
	acePanel.
		SetTitle("ACE Explorer").
		SetBorder(true)

	daclOwnerTextView = tview.NewTextView()
	daclOwnerTextView.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Owner").
		SetBorder(true)
	aceMask = tview.NewTextView()
	aceMask.
		SetTextAlign(tview.AlignCenter).
		SetTitle("ACE Mask").
		SetBorder(true)

	aceMaskBinary = tview.NewTextView()
	aceMaskBinary.
		SetTextAlign(tview.AlignCenter).
		SetTitle("ACE Mask (Binary)").
		SetBorder(true)

	controlFlagsTextView = tview.NewTextView()
	controlFlagsTextView.
		SetTextAlign(tview.AlignCenter).
		SetTitle("ControlFlags").
		SetBorder(true)

	daclEntriesPanel = tview.NewTable()
	daclEntriesPanel.
		SetFixed(1, 0).
		SetSelectable(true, false).
		SetEvaluateAllRows(true).
		SetTitle("DACL").
		SetBorder(true)

	daclEntriesPanel.SetSelectionChangedFunc(func(row, column int) {
		if sd != nil && row <= len(parsedAces) && row > 0 {
			ace := parsedAces[row-1]
			maskInt := ace.Raw.GetMask()

			aceMask.SetText(strconv.Itoa(maskInt))
			aceMaskBinary.SetText(fmt.Sprintf("%032b", maskInt))

			acePanel.Clear()

			for _, right := range ace.Mask {
				currentRight := right
				acePanel.AddItem(currentRight, "", 'x', nil)
			}
		}
	})

	daclPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(
			tview.NewFlex().
				AddItem(objectNameInputDacl, 0, 2, false).
				AddItem(daclOwnerTextView, 0, 1, false),
			3, 0, false).
		AddItem(tview.NewFlex().
			AddItem(controlFlagsTextView, 14, 0, false).
			AddItem(aceMask, 12, 0, false).
			AddItem(aceMaskBinary, 0, 1, false), 3, 0, false).
		AddItem(daclEntriesPanel, 0, 8, false)

	daclEntriesPanel.SetInputCapture(daclEntriesPanelKeyHandler)
	daclPage.SetInputCapture(daclPageKeyHandler)
	objectNameInputDacl.SetDoneFunc(func(tcell.Key) {
		queryDacl(objectNameInputDacl.GetText())
	})
}

type ParsedACE struct {
	Idx            int
	SamAccountName string
	Type           string
	Mask           []string
	Inheritance    bool
	Scope          string
	NoPropagate    bool
	Severity       int
	Raw            sdl.ACEInt
}

func selectDaclEntry(aceToSelect sdl.ACEInt) {
	for idx, ace := range parsedAces {
		if aceToSelect.Encode() == ace.Raw.Encode() {
			daclEntriesPanel.Select(idx+1, 0)
		}
	}
}

func updateDaclEntries() {
	runControlDacl.Lock()
	if runningDacl {
		runControlDacl.Unlock()
		updateLog("Another query is still running...", "yellow")
		return
	}
	runningDacl = true
	runControlDacl.Unlock()

	defer func() {
		runControlDacl.Lock()
		runningDacl = false
		runControlDacl.Unlock()
	}()

	daclEntriesPanel.Clear()
	daclOwnerTextView.SetText("")
	controlFlagsTextView.SetText("")
	aceMask.SetText("")
	aceMaskBinary.SetText("")

	daclEntriesPanel.SetCell(0, 0, tview.NewTableCell("Type").SetSelectable(false))
	daclEntriesPanel.SetCell(0, 1, tview.NewTableCell("Principal").SetSelectable(false))
	daclEntriesPanel.SetCell(0, 2, tview.NewTableCell("Access").SetSelectable(false).SetAlign(tview.AlignCenter))
	daclEntriesPanel.SetCell(0, 3, tview.NewTableCell("Inherited").SetSelectable(false).SetAlign(tview.AlignCenter))
	daclEntriesPanel.SetCell(0, 4, tview.NewTableCell("Scope").SetSelectable(false).SetAlign(tview.AlignCenter))
	daclEntriesPanel.SetCell(0, 5, tview.NewTableCell("No Propagate").SetSelectable(false).SetAlign(tview.AlignCenter))

	var hexSD string
	var readableMask string
	var aceType string
	var aceInheritance string
	var aceNoPropagate string

	object = objectNameInputDacl.GetText()
	hexSD, err = lc.GetSecurityDescriptor(object)

	sd = nil
	parsedAces = nil

	if err == nil {
		sd = sdl.NewSD(hexSD)

		numAces := strconv.Itoa(len(sd.DACL.Aces))

		updateLog("DACL obtained for '"+object+"' ("+numAces+" ACEs)", "green")
		app.SetFocus(daclEntriesPanel)
		daclEntriesPanel.ScrollToBeginning()

		controlFlags := sd.GetControl()
		controlFlagsTextView.SetText(strconv.Itoa(controlFlags))

		ownerSID := ldaputils.ConvertSID(sd.Owner)
		ownerPrincipal, err = lc.FindSamForSID(ownerSID)
		if err == nil {
			daclOwnerTextView.SetText(ownerPrincipal)
		} else {
			daclOwnerTextView.SetText("[red]" + ownerSID)
		}
		groupPrincipal, err = lc.FindSamForSID(ldaputils.ConvertSID(sd.Group))
		// For AD, groupPrincipal is not relevant,
		// so there's no need to show it in the UI

		// Parse the ACEs from the DACL in sd into parsedAces
		parseAces(&parsedAces, sd)

		for idx, entry := range parsedAces {
			if len(entry.Mask) == 1 {
				readableMask = entry.Mask[0]
			} else {
				readableMask = "Special"
			}

			if entry.Severity == 1 {
				readableMask = "[purple]" + readableMask
			} else if entry.Severity == 2 {
				readableMask = "[blue]" + readableMask
			} else if entry.Severity == 3 {
				readableMask = "[red]" + readableMask
			}

			if entry.Type == "Allow" {
				aceType = "[green]" + entry.Type
			} else {
				aceType = "[red]" + entry.Type
			}

			if entry.Inheritance {
				aceInheritance = "[green]True"
			} else {
				aceInheritance = "[red]False"
			}

			if entry.NoPropagate {
				aceNoPropagate = "[green]True"
			} else {
				aceNoPropagate = "[red]False"
			}

			principalName := entry.SamAccountName
			if ldaputils.IsSID(principalName) {
				principalName = "[red]" + principalName
			}

			daclEntriesPanel.SetCell(idx+1, 0, tview.NewTableCell(aceType))

			daclEntriesPanel.SetCell(idx+1, 1, tview.NewTableCell(principalName))

			readableMaskCell := tview.NewTableCell(readableMask).SetAlign(tview.AlignCenter)
			daclEntriesPanel.SetCell(idx+1, 2, readableMaskCell)

			daclEntriesPanel.SetCell(
				idx+1, 3, tview.NewTableCell(aceInheritance).SetAlign(tview.AlignCenter))

			daclEntriesPanel.SetCell(
				idx+1, 4, tview.NewTableCell(entry.Scope).SetAlign(tview.AlignCenter))

			daclEntriesPanel.SetCell(
				idx+1, 5, tview.NewTableCell(aceNoPropagate).SetAlign(tview.AlignCenter))
		}

		daclEntriesPanel.Select(1, 1)
	} else {
		updateLog(fmt.Sprint(err), "red")
	}
}

func daclRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case objectNameInputDacl:
		app.SetFocus(daclEntriesPanel)
	case daclEntriesPanel:
		app.SetFocus(objectNameInputDacl)
	}
}

func loadChangeOwnerForm() {
	changeOwnerForm := NewXForm()
	changeOwnerForm.
		AddTextView("Owner", ownerPrincipal, 0, 1, true, true).
		AddTextView("Group", groupPrincipal, 0, 1, true, true).
		AddInputField("New Owner", "", 0, nil, nil).
		AddInputField("New Owner SID", "", 0, nil, nil).
		AddInputField("New Group SID", "", 0, nil, nil)

	newOwnerFormItem := changeOwnerForm.GetFormItemByLabel("New Owner")
	newOwnerSIDFormItem := changeOwnerForm.GetFormItemByLabel("New Owner SID")
	newGroupSIDFormItem := changeOwnerForm.GetFormItemByLabel("New Group SID")
	newOwnerFormItem.(*tview.InputField).SetDoneFunc(func(key tcell.Key) {
		newOwnerSID := ""
		newGroupSID := ""

		text := newOwnerFormItem.(*tview.InputField).GetText()
		if ldaputils.IsSID(text) {
			_, err := lc.FindSamForSID(text)
			if err == nil {
				newOwnerSID = text
				newGroupSID, err = lc.FindPrimaryGroupForSID(newOwnerSID)
				if err != nil {
					newGroupSID, _ = lc.FindSIDForObject(groupPrincipal)
				}
			}
		} else {
			// If it's not a SID, it's a sAMAccountName or DN
			foundOwnerSid, err := lc.FindSIDForObject(text)
			if err == nil {
				newOwnerSID = foundOwnerSid
				newGroupSID, err = lc.FindPrimaryGroupForSID(newOwnerSID)
				if err != nil {
					newGroupSID, _ = lc.FindSIDForObject(groupPrincipal)
				}
			}
		}

		newOwnerSIDFormItem.(*tview.InputField).SetText(newOwnerSID)
		newGroupSIDFormItem.(*tview.InputField).SetText(newGroupSID)
	})

	changeOwnerForm.
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
		}).
		AddButton("Update", func() {
			newOwnerSID := newOwnerSIDFormItem.(*tview.InputField).GetText()
			newGroupSID := newGroupSIDFormItem.(*tview.InputField).GetText()
			if newOwnerSID == "" || newGroupSID == "" {
				updateLog("Owner SID and Group SID can't be empty", "red")
				app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
				return
			}

			encodedOwnerSID, err := ldaputils.EncodeSID(newOwnerSID)
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
				app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
				return
			}

			encodedGroupSID, err := ldaputils.EncodeSID(newGroupSID)
			if err != nil {
				updateLog(fmt.Sprint(err), "red")
				app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
				return
			}

			sd.SetOwnerAndGroup(
				string(encodedOwnerSID),
				string(encodedGroupSID),
			)

			newSd, _ := hex.DecodeString(sd.Encode())

			err = lc.ModifyDACL(object, string(newSd))

			if err == nil {
				newOwner := changeOwnerForm.GetFormItemByLabel("New Owner").(*tview.InputField).GetText()

				updateLog("Owner for '"+object+"' changed to '"+newOwner+"'", "green")

				go app.QueueUpdateDraw(updateDaclEntries)
			} else {
				updateLog(fmt.Sprint(err), "red")
			}
			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
		})

	changeOwnerForm.
		SetTitle("Change DACL Owner (" + object + ")").
		SetBorder(true)

	//assignFormTheme(changeOwnerForm)

	changeOwnerForm.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
			return nil
		}
		return event
	})

	app.SetRoot(changeOwnerForm, true).SetFocus(changeOwnerForm)
}

func loadChangeControlFlagsForm() {
	if sd == nil {
		return
	}

	updateControlFlagsForm := NewXForm()

	controlFlags := sd.GetControl()

	checkboxState := controlFlags

	updateControlFlagsForm.
		AddTextView("Raw ControlFlag Value", strconv.Itoa(checkboxState), 0, 1, false, true)

	controlFlagsKeys := make([]int, 0)
	for key := range ldaputils.SDControlFlags {
		controlFlagsKeys = append(controlFlagsKeys, key)
	}
	sort.Ints(controlFlagsKeys)

	for _, val := range controlFlagsKeys {
		flagVal := val
		updateControlFlagsForm.AddCheckbox(
			ldaputils.SDControlFlags[flagVal],
			controlFlags&flagVal != 0,
			func(checked bool) {
				if checked {
					checkboxState |= flagVal
				} else {
					checkboxState &^= flagVal
				}

				flagPreview := updateControlFlagsForm.GetFormItemByLabel("Raw ControlFlag Value").(*tview.TextView)
				if flagPreview != nil {
					flagPreview.SetText(strconv.Itoa(checkboxState))
				}
			})
	}

	updateControlFlagsForm.
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
		}).
		AddButton("Update", func() {

			sd.Header.Control = ldaputils.EndianConvert(fmt.Sprintf("%04x", checkboxState))
			newSd, _ := hex.DecodeString(sd.Encode())

			err = lc.ModifyDACL(object, string(newSd))

			if err == nil {
				updateLog("Control flags updated for '"+object+"'", "green")
				go app.QueueUpdateDraw(updateDaclEntries)
			} else {
				updateLog(fmt.Sprint(err), "red")
			}

			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
		})

	updateControlFlagsForm.SetTitle("ControlFlags Editor").SetBorder(true)

	//assignFormTheme(updateControlFlagsForm)
	updateControlFlagsForm.SetItemPadding(0)

	app.SetRoot(updateControlFlagsForm, true).SetFocus(updateControlFlagsForm)
}

func exportCurrentSD() {
	if sd == nil {
		updateLog("An object was not queried yet", "red")
		return
	}

	encodedSD := sd.Encode()

	exportMap := make(map[string]any)
	exportMap["Query"] = object
	exportMap["HexSD"] = encodedSD

	exportMap["ParsedDACL"] = parsedAces

	writeDataExport(exportMap, "sd", "security_descriptor")
}

func daclPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		daclRotateFocus()
		return nil
	}

	if sd == nil {
		return event
	}

	switch event.Key() {
	case tcell.KeyCtrlO:
		loadChangeOwnerForm()
		return nil
	case tcell.KeyCtrlK:
		loadChangeControlFlagsForm()
		return nil
	case tcell.KeyCtrlS:
		exportCurrentSD()
		return nil
	}

	return event
}

func daclEntriesPanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if sd == nil {
		return event
	}

	switch event.Key() {
	case tcell.KeyDelete:
		selectionIdx, _ := daclEntriesPanel.GetSelection()
		loadDeleteAceForm(selectionIdx)
		return nil
	case tcell.KeyCtrlN:
		loadAceEditorForm(-1)
		return nil
	case tcell.KeyCtrlE:
		selectionIdx, _ := daclEntriesPanel.GetSelection()
		loadAceEditorForm(selectionIdx)
		return nil
	}

	return event
}
