package tui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func handleEscape(returnFocus tview.Primitive) func(*tcell.EventKey) *tcell.EventKey {
	return func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(returnFocus)
			return nil
		}
		return event
	}
}
