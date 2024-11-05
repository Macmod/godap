package tui

import (
	"github.com/rivo/tview"
)

var (
	helpPage         *tview.Flex
	keybindingsPanel *tview.Table
)

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

` + GodapVer

	keybindings := [][]string{
		{"Ctrl + Enter", "Global", "Next panel"},
		{"f", "Global", "Toggle attribute formatting"},
		{"e", "Global", "Toggle emojis"},
		{"c", "Global", "Toggle colors"},
		{"a", "Global", "Toggle attribute expansion for multi-value attributes"},
		{"d", "Global", "Toggle \"include deleted objects\" flag"},
		{"l", "Global", "Change current server address & credentials"},
		{"Ctrl + r", "Global", "Reconnect to the server"},
		{"Ctrl + u", "Global", "Upgrade connection to use TLS (with StartTLS)"},
		{"Ctrl + f", "Explorer & Object Search pages", "Open the finder to search for cached objects & attributes with regex"},
		{"Left Arrow", "Explorer panel", "Collapse the children of the selected object"},
		{"Right Arrow", "Explorer panel", "Expand the children of the selected object"},
		{"r", "Explorer panel", "Reload the attributes and children of the selected object"},
		{"Ctrl + n", "Explorer panel", "Create a new object under the selected object"},
		{"Ctrl + s", "Explorer panel", "Export all loaded nodes in the selected subtree into a JSON file"},
		{"Ctrl + p", "Explorer panel", "Change the password of the selected user or computer account"},
		{"Ctrl + a", "Explorer panel", "Update the userAccountControl of the object interactively"},
		{"Ctrl + l", "Explorer panel", "Move the selected object to another location"},
		{"Delete", "Explorer panel", "Delete the selected object"},
		{"Ctrl + e", "Attributes panel", "Edit the selected attribute of the selected object"},
		{"Ctrl + n", "Attributes panel", "Create a new attribute in the selected object"},
		{"Delete", "Attributes panel", "Delete the selected attribute of the selected object"},
		{"Enter", "Attributes panel (entries hidden)", "Expand all hidden entries of an attribute"},
		{"Delete", "Groups panels", "Remove the selected member from the searched group or vice-versa"},
		{"Ctrl + s", "Object groups panel", "Export the current groups innto a JSON file"},
		{"Ctrl + s", "Group members panel", "Export the current group members into a JSON file"},
		{"Ctrl + g", "Groups panels / Explorer panel / Obj. Search panel", "Add a member to the selected group / add the selected object into a group"},
		{"Ctrl + d", "Groups panels / Explorer panel / Obj. Search panel", "Inspect the DACL of the currently selected object"},
		{"Ctrl + o", "DACL page", "Change the owner of the current security descriptor"},
		{"Ctrl + k", "DACL page", "Change the control flags of the current security descriptor"},
		{"Ctrl + s", "DACL page", "Export the current security descriptor into a JSON file"},
		{"Ctrl + n", "DACL entries panel", "Create a new ACE in the current DACL"},
		{"Ctrl + e", "DACL entries panel", "Edit the selected ACE of the current DACL"},
		{"Delete", "DACL entries panel", "Deletes the selected ACE of the current DACL"},
		{"Ctrl + s", "GPO page", "Export the current GPOs and their links into a JSON file"},
		{"Ctrl + s", "DNS zones panel", "Export the selected zones and their child DNS nodes into a JSON file"},
		{"r", "DNS zones panel", "Reload the nodes of the selected zone / the records of the selected node"},
		{"h", "Global", "Show/hide headers"},
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
