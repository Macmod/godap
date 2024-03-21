package main

import (
	"github.com/rivo/tview"
)

var helpPage *tview.Flex
var keybindingsPanel *tview.Table

func initHelpPage() {
	helpText := `[blue]
 _______  _______  ______   _______  _______ 
(  ____ \(  ___  )(  __  \ (  ___  )(  ____ )
| (    \/| (   ) || (  \  )| (   ) || (    )|
| |      | |   | || |   ) || (___) || (____)|
| | ____ | |   | || |   | ||  ___  ||  _____)
| | \_  )| |   | || |   ) || (   ) || (      
| (___) || (___) || (__/  )| )   ( || )      
(_______)(_______)(______/ |/     \||/       

` + godapVer

	keybindings := [][]string{
		{"Ctrl + Enter", "Global", "Next panel"},
		{"f / F", "Global", "Toggle attribute formatting"},
		{"e / E", "Global", "Toggle emojis"},
		{"c / C", "Global", "Toggle colors"},
		{"a / A", "Global", "Toggle attribute expansion for multi-value attributes"},
		{"d / D", "Global", "Toggle \"include deleted objects\" flag"},
		{"l / L", "Global", "Change current server address & credentials"},
		{"Ctrl + r / R", "Global", "Reconnect to the server"},
		{"Ctrl + u / U", "Global", "Upgrade connection to use TLS (with StartTLS)"},
		{"Ctrl + f", "LDAP Explorer & Object Search pages", "Open the finder to search for cached objects & attributes with regex"},
		{"Left Arrow", "Explorer panel", "Collapse the children of the selected object"},
		{"Right Arrow", "Explorer panel", "Expand the children of the selected object"},
		{"r / R", "Explorer panel", "Reload the attributes and children of the selected object"},
		{"Ctrl + n / N", "Explorer panel", "Create a new object under the selected object"},
		{"Ctrl + s / S", "Explorer panel", "Export all loaded nodes in the selected subtree into a JSON file"},
		{"Ctrl + p / P", "Explorer panel", "Change the password of the selected user or computer account"},
		{"Ctrl + a / A", "Explorer panel", "Update the userAccountControl of the object interactively"},
		{"Ctrl + l / L", "Explorer panel", "Move the selected object to another location"},
		{"Delete", "Explorer panel", "Delete the selected object"},
		{"Ctrl + e / E", "Attributes panel", "Edit the selected attribute of the selected object"},
		{"Ctrl + n / N", "Attributes panel", "Create a new attribute in the selected object"},
		{"Delete", "Attributes panel", "Delete the selected attribute of the selected object"},
		{"Ctrl + o / O", "DACL page", "Change the owner of the current DACL"},
		{"Ctrl + k / K", "DACL page", "Change the control flags of the current DACL"},
		{"Ctrl + n / N", "DACL entries panel", "Create a new ACE in the current DACL"},
		{"Ctrl + e / E", "DACL entries panel", "Edit the selected ACE of the current DACL"},
		{"Delete", "DACL entries panel", "Deletes the selected ACE of the current DACL"},
		{"h / H", "Global", "Show/hide headers"},
		{"q", "Global", "Exit the program"},
	}

	// Create a table
	keybindingsPanel = tview.NewTable().
		SetSelectable(true, false).
		SetEvaluateAllRows(true).
		SetFixed(1, 0)

	headers := []string{"Keybinding", "Context", "Action"}
	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tview.Styles.SecondaryTextColor).
			SetAlign(tview.AlignCenter).SetSelectable(false)
		keybindingsPanel.SetCell(0, col, cell)
	}

	for row, binding := range keybindings {
		for col, value := range binding {
			cell := tview.NewTableCell(value).
				SetTextColor(tview.Styles.PrimaryTextColor).
				SetAlign(tview.AlignLeft)
			keybindingsPanel.SetCell(row+1, col, cell)
		}
	}

	keybindingsPanel.Select(1, 0)

	helpTextView := tview.NewTextView().
		SetText(helpText).
		SetTextAlign(tview.AlignCenter).
		SetDynamicColors(true)

	frame := tview.NewFrame(keybindingsPanel)
	frame.SetBorders(0, 0, 0, 0, 0, 0).
		SetTitleAlign(tview.AlignCenter).
		SetTitle(" Keybindings ")

	helpPage = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(helpTextView, 12, 0, true).
		AddItem(frame, 0, 2, false)
}
