package tui

import (
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
)

type GodapTheme struct {
	TViewTheme tview.Theme

	// Input fields
	FieldBackgroundColor tcell.Color
	PlaceholderStyle     tcell.Style
	PlaceholderTextColor tcell.Color

	// Form buttons
	FormButtonStyle           tcell.Style
	FormButtonTextColor       tcell.Color
	FormButtonBackgroundColor tcell.Color
	FormButtonActivatedStyle  tcell.Style

	// Tree node colors
	RecycledNodeColor tcell.Color
	DeletedNodeColor  tcell.Color
	DisabledNodeColor tcell.Color
}

// Theme definitions - controls the colors of all Godap pages
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

var DefaultTheme = GodapTheme{
	// Base TView theme
	TViewTheme: baseTheme,

	// Input fields for main pages
	FieldBackgroundColor: tcell.ColorBlack,
	PlaceholderStyle:     tcell.Style{}.Foreground(tcell.ColorGray).Background(tcell.ColorBlack),
	PlaceholderTextColor: tcell.ColorGray,

	// Form buttons
	FormButtonStyle:           tcell.Style{}.Background(tcell.ColorWhite),
	FormButtonTextColor:       tcell.ColorBlack,
	FormButtonBackgroundColor: tcell.ColorWhite,
	FormButtonActivatedStyle:  tcell.StyleDefault.Background(tcell.ColorGray),

	// Tree node colors
	RecycledNodeColor: tcell.ColorRed,
	DeletedNodeColor:  tcell.ColorGray,
	DisabledNodeColor: tcell.ColorYellow,
}

// Helpers to assign themes manually to primitives
// TODO: Refactor again
func assignInputFieldTheme(input *tview.InputField) {
	input.SetPlaceholderStyle(DefaultTheme.PlaceholderStyle).
		SetPlaceholderTextColor(DefaultTheme.PlaceholderTextColor).
		SetFieldBackgroundColor(DefaultTheme.FieldBackgroundColor)
}

func assignButtonTheme(btn *tview.Button) {
	btn.SetStyle(DefaultTheme.FormButtonStyle).
		SetLabelColor(DefaultTheme.FormButtonTextColor).
		SetActivatedStyle(DefaultTheme.FormButtonActivatedStyle)
}

func assignDropDownTheme(dropdown *tview.DropDown) {
	dropdown.SetFieldBackgroundColor(DefaultTheme.FieldBackgroundColor)
}

// Form customizations
type XForm struct {
	*tview.Form
}

func NewXForm() *XForm {
	return &XForm{
		tview.NewForm().
			SetFieldBackgroundColor(DefaultTheme.FieldBackgroundColor).
			SetButtonBackgroundColor(DefaultTheme.FormButtonBackgroundColor).
			SetButtonTextColor(DefaultTheme.FormButtonTextColor).
			SetButtonActivatedStyle(DefaultTheme.FormButtonActivatedStyle),
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
		SetPlaceholderStyle(DefaultTheme.PlaceholderStyle).
		SetPlaceholderTextColor(DefaultTheme.PlaceholderTextColor).
		SetLabel(label).
		SetText(value).
		SetFieldWidth(fieldWidth).
		SetAcceptanceFunc(accept).
		SetChangedFunc(changed))

	return f
}

func (f *XForm) AddTextArea(label string, text string, fieldWidth, fieldHeight int, maxLength int, changed func(text string)) *XForm {
	if fieldHeight == 0 {
		fieldHeight = tview.DefaultFormFieldHeight
	}

	textArea := tview.NewTextArea()
	textArea.
		SetLabel(label).
		SetSize(fieldHeight, fieldWidth).
		SetMaxLength(maxLength).
		SetPlaceholderStyle(DefaultTheme.PlaceholderStyle)

	if text != "" {
		textArea.SetText(text, true)
	}

	if changed != nil {
		textArea.SetChangedFunc(func() {
			changed(textArea.GetText())
		})
	}

	f.AddFormItem(textArea)

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
		SetFieldBackgroundColor(DefaultTheme.FieldBackgroundColor).
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

func GetEntryColor(entry *ldap.Entry) (tcell.Color, bool) {
	isDeleted := strings.ToLower(entry.GetAttributeValue("isDeleted")) == "true"
	isRecycled := strings.ToLower(entry.GetAttributeValue("isRecycled")) == "true"

	if isDeleted {
		if isRecycled {
			return DefaultTheme.RecycledNodeColor, true
		} else {
			return DefaultTheme.DeletedNodeColor, true
		}
	} else {
		uac := entry.GetAttributeValue("userAccountControl")
		uacNum, err := strconv.Atoi(uac)

		if err == nil && uacNum&2 != 0 {
			return DefaultTheme.DisabledNodeColor, true
		}
	}

	return baseTheme.PrimaryTextColor, false
}

func GetAttrCellColor(cellName string, cellValue string) (string, bool) {
	var color = ""

	switch cellName {
	case "lastLogonTimestamp", "accountExpires", "badPasswordTime", "lastLogoff", "lastLogon", "pwdLastSet", "creationTime", "lockoutTime":
		intValue, err := strconv.ParseInt(cellValue, 10, 64)
		if err == nil {
			unixTime := (intValue - 116444736000000000) / 10000000
			t := time.Unix(unixTime, 0).UTC()

			daysDiff := int(time.Since(t).Hours() / 24)

			if daysDiff <= 7 {
				color = "green"
			} else if daysDiff <= 90 {
				color = "yellow"
			} else {
				color = "red"
			}
		}
	case "objectGUID", "objectSid":
		color = "gray"
	case "whenCreated", "whenChanged":
		layout := "20060102150405.0Z"
		t, err := time.Parse(layout, cellValue)
		if err == nil {
			daysDiff := int(time.Since(t).Hours() / 24)

			if daysDiff <= 7 {
				color = "green"
			} else if daysDiff <= 90 {
				color = "yellow"
			} else {
				color = "red"
			}
		}
	}

	switch cellValue {
	case "TRUE", "Enabled", "Normal", "PwdNotExpired":
		color = "green"
	case "FALSE", "NotNormal", "PwdExpired":
		color = "red"
	case "Disabled":
		color = "yellow"
	}

	if color != "" {
		return color, true
	}

	return "", false
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
