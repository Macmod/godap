package main

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var baseTheme tview.Theme = tview.Theme{
	PrimitiveBackgroundColor:    tcell.ColorBlack,
	ContrastBackgroundColor:     tcell.ColorBlue,
	MoreContrastBackgroundColor: tcell.ColorGreen,
	BorderColor:                 tcell.ColorWhite,
	TitleColor:                  tcell.ColorWhite,
	GraphicsColor:               tcell.ColorWhite,
	PrimaryTextColor:            tcell.ColorWhite,
	SecondaryTextColor:          tcell.ColorYellow,
	TertiaryTextColor:           tcell.ColorGreen,
	InverseTextColor:            tcell.ColorBlue,
	ContrastSecondaryTextColor:  tcell.ColorNavy,
}

// Input fields for main pages
var fieldBackgroundColor = tcell.ColorBlack

var placeholderStyle = tcell.Style{}.
	Foreground(tcell.ColorDefault).
	Background(fieldBackgroundColor)

var placeholderTextColor = tcell.ColorGray

// Form buttons
var formButtonStyle = tcell.Style{}.
	Background(tcell.ColorWhite)

var formButtonTextColor = tcell.ColorBlack
var formButtonBackgroundColor = tcell.ColorWhite
var formButtonActivatedStyle = tcell.StyleDefault.Background(tcell.ColorGray)

// Form customizations
type XForm struct {
	*tview.Form
}

func NewXForm() *XForm {
	return &XForm{
		tview.NewForm().
			SetFieldBackgroundColor(tcell.ColorBlack),
	}
}

func (f *XForm) AddTextView(label, text string, fieldWidth, fieldHeight int, dynamicColors, scrollable bool) *XForm {
	if fieldHeight == 0 {
		fieldHeight = tview.DefaultFormFieldHeight
	}

	textView := tview.NewTextView()
	f.AddFormItem(textView.
		SetLabel(label).
		SetSize(fieldHeight, fieldWidth).
		SetDynamicColors(dynamicColors).
		SetScrollable(scrollable).
		SetText(text))

	return f
}

func (f *XForm) AddInputField(label, value string, fieldWidth int, accept func(textToCheck string, lastChar rune) bool, changed func(text string)) *XForm {
	inputField := tview.NewInputField()
	f.AddFormItem(inputField.
		SetFieldStyle(tcell.StyleDefault.Background(tcell.ColorWhite).Foreground(tcell.ColorBlack)).
		SetLabel(label).
		SetText(value).
		SetFieldWidth(fieldWidth).
		SetAcceptanceFunc(accept).
		SetChangedFunc(changed))

	return f
}

func (f *XForm) AddPasswordField(label, value string, fieldWidth int, mask rune, changed func(text string)) *XForm {
	if mask == 0 {
		mask = '*'
	}

	f.AddFormItem(tview.NewInputField().
		SetFieldTextColor(tcell.ColorBlack).
		SetLabel(label).
		SetText(value).
		SetFieldWidth(fieldWidth).
		SetMaskCharacter(mask).
		SetChangedFunc(changed))

	return f
}

func (f *XForm) AddDropDown(label string, options []string, initialOption int, selected func(option string, optionIndex int)) *XForm {
	dropdown := tview.NewDropDown()
	dropdown.
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetLabel(label).
		SetOptions(options, selected).
		SetCurrentOption(initialOption)

	f.AddFormItem(dropdown)

	return f
}

func (f *XForm) AddCheckbox(label string, checked bool, changed func(checked bool)) *XForm {
	f.AddFormItem(
		tview.NewCheckbox().
			//SetCheckedStyle(tcell.StyleDefault.Background(tcell.ColorGreen).Foreground(tcell.ColorWhite)).
			//SetUncheckedStyle(tcell.StyleDefault.Background(tcell.ColorRed).Foreground(tcell.ColorWhite)).
			SetCheckedString("True").
			SetUncheckedString("False").
			SetLabel(label).
			SetChecked(checked).
			SetChangedFunc(changed),
	)

	return f
}

// Strangely, tview.Button does not implement FormItem yet,
// otherwise we could do button customizations
// with the same abstraction
/*
func (f *XForm) AddButton(label string, selected func()) *Form {
	return f.AddFormItem(
		tview.NewButton(label).
			SetSelectedFunc(selected),
	)
}
*/
