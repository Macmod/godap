package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Macmod/godap/sdl"
	"github.com/gdamore/tcell/v2"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var daclPage *tview.Flex
var objectNameInputDacl *tview.InputField
var daclEntriesPanel *tview.Table
var daclOwner *tview.InputField
var acePanel *tview.List
var aceMask *tview.InputField
var aceMaskBinary *tview.InputField
var readableAces []sdl.ACESList

func InitDaclPage() {
	objectNameInputDacl = tview.NewInputField()
	objectNameInputDacl.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("Object (sAMAccountName or DN)").
		SetBorder(true)

	acePanel = tview.NewList()
	acePanel.
		SetTitle("ACE Explorer").
		SetBorder(true)

	daclOwner = tview.NewInputField()
	daclOwner.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("Owner").
		SetBorder(true)
	daclOwner.SetDisabled(true)

	aceMask = tview.NewInputField()
	aceMask.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("Mask").
		SetBorder(true)
	aceMask.SetDisabled(true)

	aceMaskBinary = tview.NewInputField()
	aceMaskBinary.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("BinMask").
		SetBorder(true)
	aceMaskBinary.SetDisabled(true)

	daclEntriesPanel = tview.NewTable()
	daclEntriesPanel.
		SetFixed(1, 0).
		SetSelectable(true, false).
		SetBorders(true).
		SetTitle("DACL")
	daclEntriesPanel.SetBorder(true)

	daclEntriesPanel.SetSelectionChangedFunc(func(row, column int) {
		if row < len(readableAces) && row > 0 {
			ace := readableAces[row-1]
			aceMask.SetText(strconv.Itoa(ace.RawMask))
			aceMaskBinary.SetText(fmt.Sprintf("%032b", ace.RawMask))

			acePanel.Clear()

			for _, right := range ace.Mask {
				acePanel.AddItem(right, "", 'x', nil)
			}
		}
	})

	daclPage = tview.NewFlex().
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(objectNameInputDacl, 3, 0, false).
				AddItem(daclEntriesPanel, 0, 8, false),
			0, 2, false,
		).
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(daclOwner, 3, 0, false).
				AddItem(
					tview.NewFlex().
						AddItem(aceMask, 0, 1, false).
						AddItem(aceMaskBinary, 34, 0, false),
					3, 0, false,
				).
				AddItem(acePanel, 0, 6, false),
			0, 1, false,
		)

	daclPage.SetInputCapture(daclPageKeyHandler)
	objectNameInputDacl.SetDoneFunc(func(key tcell.Key) {
		daclEntriesPanel.Clear()

		daclEntriesPanel.SetCell(0, 0, tview.NewTableCell("Type").SetSelectable(false))
		daclEntriesPanel.SetCell(0, 1, tview.NewTableCell("sAMAccountName").SetSelectable(false))
		daclEntriesPanel.SetCell(0, 2, tview.NewTableCell("Access").SetSelectable(false))
		daclEntriesPanel.SetCell(0, 3, tview.NewTableCell("Inherited").SetSelectable(false))
		daclEntriesPanel.SetCell(0, 4, tview.NewTableCell("Applies to").SetSelectable(false))

		var hexSD string
		var readableMask string
		var aceType string
		var aceInheritance string
		var owner string

		object := objectNameInputDacl.GetText()
		hexSD, err = getSecurityDescriptor(lc.Conn, object)

		if err == nil {
			updateLog("DACL obtained for object '"+object+"'", "green")
			readableAces, owner = sdl.ParseSD(lc.Conn, rootDN, hexSD)
			daclOwner.SetText(owner)

			for idx, val := range readableAces {
				if len(val.Mask) == 1 {
					readableMask = val.Mask[0]
				} else {
					readableMask = "Special"
				}

				if val.Severity == 1 {
					readableMask = "[purple]" + readableMask
				} else if val.Severity == 2 {
					readableMask = "[blue]" + readableMask
				} else if val.Severity == 3 {
					readableMask = "[red]" + readableMask
				}

				if val.Type == "Allow" {
					aceType = "[green]" + val.Type
				} else {
					aceType = "[red]" + val.Type
				}

				if val.Inheritance {
					aceInheritance = "[green]True"
				} else {
					aceInheritance = "[red]False"
				}

				daclEntriesPanel.SetCell(idx+1, 0, tview.NewTableCell(aceType))

				daclEntriesPanel.SetCell(idx+1, 1, tview.NewTableCell(val.SamAccountName))

				readableMaskCell := tview.NewTableCell(readableMask).SetAlign(tview.AlignCenter)
				daclEntriesPanel.SetCell(idx+1, 2, readableMaskCell)

				daclEntriesPanel.SetCell(
					idx+1, 3, tview.NewTableCell(aceInheritance).SetAlign(tview.AlignCenter))

				daclEntriesPanel.SetCell(
					idx+1, 4, tview.NewTableCell(val.Scope).SetAlign(tview.AlignCenter))
			}

			daclEntriesPanel.Select(1, 1)
		} else {
			updateLog(fmt.Sprint(err), "red")
		}
	})
}

type ControlMicrosoftSDFlags struct {
	Criticality  bool
	ControlValue int32
}

func (c *ControlMicrosoftSDFlags) GetControlType() string {
	return "1.2.840.113556.1.4.801"
}

func (c *ControlMicrosoftSDFlags) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "1.2.840.113556.1.4.801", "Control Type"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value(SDFlags)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlags")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.ControlValue, "Flags"))
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

func (c *ControlMicrosoftSDFlags) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %d", "1.2.840.113556.1.4.801",
		"1.2.840.113556.1.4.801", c.Criticality, c.ControlValue)
}

func getSecurityDescriptor(conn *ldap.Conn, object string) (queryResult string, err error) {
	query := fmt.Sprintf("(samaccountname=%s)", object)
	if strings.Contains(object, "=") {
		query = fmt.Sprintf("(distinguishedName=%s)", object)
	}

	searchReq := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		query,
		[]string{"nTSecurityDescriptor"},
		[]ldap.Control{&ControlMicrosoftSDFlags{ControlValue: 7}},
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return "", err
	}

	if len(result.Entries) > 0 {
		sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
		hexSD := hex.EncodeToString(sd)
		return hexSD, nil
	}

	return "", fmt.Errorf("Object not found")
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

func daclPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		daclRotateFocus()
		return nil
	}

	return event
}
