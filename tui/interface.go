package tui

import (
	"strconv"

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

func getParentNode(node *tview.TreeNode, tree *tview.TreeView) *tview.TreeNode {
	pathToCurrent := tree.GetPath(node)

	if len(pathToCurrent) > 1 {
		return pathToCurrent[len(pathToCurrent)-2]
	}

	return nil
}

func findEntryInChildren(dn string, parent *tview.TreeNode) int {
	siblings := parent.GetChildren()

	for idx, loopNode := range siblings {
		if loopNode.GetReference().(string) == dn {
			return idx
		}
	}

	return -1
}

func numericAcceptanceFunc(textToCheck string, lastChar rune) bool {
	_, err := strconv.Atoi(textToCheck)
	return err == nil
}
