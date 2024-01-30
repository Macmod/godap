package main

import (
	"encoding/hex"
	"fmt"

	//"strconv"
	//"strings"
	"github.com/Macmod/godap/sdl"
	"github.com/gdamore/tcell/v2"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

var daclPage *tview.Flex
var userNameInputDacl *tview.InputField
var daclEntriesPanel *tview.Table

func InitDaclPage() {
	userNameInputDacl = tview.NewInputField()
	userNameInputDacl.
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetTitle("User (sAMAccountName or DN)").
		SetBorder(true)

	daclEntriesPanel = tview.NewTable()
	daclEntriesPanel.
		SetFixed(1, 1).
		SetSelectable(true, true).
		SetBorders(true).
		SetTitle("Relevant DACLs").
		SetBorder(true)

	daclPage = tview.NewFlex().
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(userNameInputDacl, 3, 0, false).
				AddItem(daclEntriesPanel, 0, 8, false),
			0, 1, false,
		)

	daclPage.SetInputCapture(daclPageKeyHandler)
	userNameInputDacl.SetDoneFunc(func(key tcell.Key) {
		daclEntriesPanel.Clear()

		daclEntriesPanel.SetCell(0, 0, tview.NewTableCell("sAMAccountName"))
		daclEntriesPanel.SetCell(0, 1, tview.NewTableCell("GenericAll"))
		daclEntriesPanel.SetCell(0, 2, tview.NewTableCell("Write"))
		daclEntriesPanel.SetCell(0, 3, tview.NewTableCell("WriteOwner"))
		daclEntriesPanel.SetCell(0, 4, tview.NewTableCell("WriteDACL"))
		daclEntriesPanel.SetCell(0, 5, tview.NewTableCell("ForceChangePassword"))
		daclEntriesPanel.SetCell(0, 6, tview.NewTableCell("AddMember"))

		var hexSD string

		user := userNameInputDacl.GetText()
		hexSD, err = getSecurityDescriptor(lc.Conn, user)
		if err == nil {
			updateLog("DACL obtained for user '"+user+"'", "green")
			readableAces := sdl.ParseSD(lc.Conn, rootDN, hexSD)
			for idx, val := range readableAces {
				daclEntriesPanel.SetCell(idx+1, 0, tview.NewTableCell(val.SamAccountName))

				if val.GENERIC_ALL {
					daclEntriesPanel.SetCell(
						idx+1, 1, tview.NewTableCell("YES").SetAlign(tview.AlignCenter))
				}
				if val.GENERIC_WRITE {
					daclEntriesPanel.SetCell(
						idx+1, 2, tview.NewTableCell("YES").SetAlign(tview.AlignCenter))
				}
				if val.WRITE_OWNER {
					daclEntriesPanel.SetCell(
						idx+1, 3, tview.NewTableCell("YES").SetAlign(tview.AlignCenter))
				}
				if val.WRITE_DACL {
					daclEntriesPanel.SetCell(
						idx+1, 4, tview.NewTableCell("YES").SetAlign(tview.AlignCenter))
				}
				if val.FORCE_CHANGE_PASSWORD {
					daclEntriesPanel.SetCell(
						idx+1, 5, tview.NewTableCell("YES").SetAlign(tview.AlignCenter))
				}
				if val.ADD_MEMBER {
					daclEntriesPanel.SetCell(
						idx+1, 6, tview.NewTableCell("YES").SetAlign(tview.AlignCenter))
				}
			}
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

func getSecurityDescriptor(conn *ldap.Conn, user string) (queryResult string, err error) {
	query := fmt.Sprintf("(samaccountname=%s)", user)
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

	return "", fmt.Errorf("User not found")
}

func daclRotateFocus() {
	currentFocus := app.GetFocus()

	switch currentFocus {
	case userNameInputDacl:
		app.SetFocus(daclEntriesPanel)
	case daclEntriesPanel:
		app.SetFocus(userNameInputDacl)
	}
}

func daclPageKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyTab || event.Key() == tcell.KeyBacktab {
		daclRotateFocus()
		return nil
	}

	return event
}
