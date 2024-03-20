package main

import (
	"regexp"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func highlightStr(base string, idxBegin int, idxEnd int, color string) string {
	return base[:idxBegin] + "[" + color + "]" + base[idxBegin:idxEnd] + "[white]" + base[idxEnd:]
}

func openFinder(cache *EntryCache, titleLabel string) {
	currentFocus := app.GetFocus()

	numCache := tview.NewTextView().
		SetTextAlign(tview.AlignCenter)
	numCache.SetTitle("# CachedObjs")
	numCache.SetBorder(true)
	numCache.SetText(strconv.Itoa(cache.Length()))

	numResults := tview.NewTextView().
		SetTextAlign(tview.AlignCenter)
	numResults.SetTitle("# Results")
	numResults.SetBorder(true)

	inputField := tview.NewInputField()
	inputField.
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholderTextColor(placeholderTextColor).
		SetFieldBackgroundColor(fieldBackgroundColor).
		SetPlaceholder("Enter a regexp to search here").
		SetTitle("Search Query").
		SetBorder(true)

	table := tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetBorders(false)
	table.
		SetTitle("Search Results").
		SetBorder(true)

	inputField.SetDoneFunc(func(tcell.Key) {
		table.Clear()

		queryRegexp, err := regexp.Compile(inputField.GetText())
		if err == nil {
			results := cache.FindWithRegexp(queryRegexp)
			if len(results) != 0 {
				table.SetCell(0, 0, tview.NewTableCell("Match").SetSelectable(false))
				table.SetCell(0, 1, tview.NewTableCell("Object").SetSelectable(false))
				table.SetCell(0, 2, tview.NewTableCell("AttrName").SetSelectable(false))
				table.SetCell(0, 3, tview.NewTableCell("AttrValue").SetSelectable(false))
				table.SetCell(0, 4, tview.NewTableCell("ValIdx").SetSelectable(false))
			}

			numResults.SetText(strconv.Itoa(len(results)))
			if len(results) == 0 {
				numResults.SetTextColor(tcell.ColorRed)
			} else {
				numResults.SetTextColor(tcell.ColorDefault)
			}

			for idx, val := range results {
				matchField := val.MatchField
				matchDN := val.MatchDN
				matchAttrName := val.MatchAttrName
				matchAttrVal := val.MatchAttrVal
				matchAttrValIdx := strconv.Itoa(val.MatchAttrValIdx)
				matchBegin := val.MatchPosBegin
				matchEnd := val.MatchPosEnd

				switch matchField {
				case "ObjectDN":
					matchDN = highlightStr(matchDN, matchBegin, matchEnd, "green")
					matchField = "[blue]" + matchField
					matchAttrValIdx = ""
				case "AttrName":
					matchAttrName = highlightStr(matchAttrName, matchBegin, matchEnd, "green")
					matchField = "[violet]" + matchField
					matchAttrValIdx = ""
				case "AttrVal":
					matchAttrVal = highlightStr(matchAttrVal, matchBegin, matchEnd, "green")
					matchField = "[purple]" + matchField
				}

				table.SetCell(idx+1, 0, tview.NewTableCell(matchField))
				table.SetCell(idx+1, 1, tview.NewTableCell(matchDN))
				table.SetCell(idx+1, 2, tview.NewTableCell(matchAttrName))
				table.SetCell(idx+1, 3, tview.NewTableCell(matchAttrVal))
				table.SetCell(idx+1, 4, tview.NewTableCell(matchAttrValIdx))
			}
		}
	})

	cancelBtn := tview.NewButton("Go Back")
	cancelBtn.SetSelectedFunc(func() {
		app.SetRoot(appPanel, true).SetFocus(currentFocus)
	})

	finderPanel := tview.NewFlex().SetDirection(tview.FlexRow)
	finderPanel.
		AddItem(
			tview.NewFlex().
				AddItem(inputField, 0, 1, false).
				AddItem(numCache, 14, 0, false).
				AddItem(numResults, 13, 0, false), 3, 0, false).
		AddItem(table, 0, 3, false).
		AddItem(cancelBtn, 1, 0, false)

	finderPanel.SetTitle("Cache Finder (" + titleLabel + ")")
	finderPanel.SetBorder(true)

	finderPanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			return nil
		}

		return event
	})

	app.SetRoot(finderPanel, true).SetFocus(inputField)
}
