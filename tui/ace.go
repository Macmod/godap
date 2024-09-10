package tui

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/Macmod/godap/v2/pkg/sdl"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	// Schema vars
	revClassGuids               map[string]string = make(map[string]string)
	revAttrGuids                map[string]string = make(map[string]string)
	revExtendedGuids            map[string]string = make(map[string]string)
	revValidatedWriteRightGuids map[string]string = make(map[string]string)
	classVals                   []string
	extendedVals                []string
	attributesVals              []string
	validatedWriteRightsVals    []string
	rights                      map[string]int = sdl.AccessRightsMap
	normalRights                map[string]int
	normalRightsVals            []string

	// UI stuff
	aceEditorPage           *tview.Flex
	permsPanel              *tview.Flex
	normalPermsForm         *tview.Form
	objectPermsForm         *tview.Form
	propertyPermsForm       *XForm
	controlPermsForm        *tview.Form
	validatedWritePermsForm *tview.Form
	newAceTable             *tview.Table
)

func loadRightVars() {
	normalRights = map[string]int{
		// List object is usually hidden from AD,
		// but should be included for completeness
		"List contents":            rights["RIGHT_DS_LIST_CONTENTS"],
		"List object":              rights["RIGHT_DS_LIST_OBJECT"],
		"Read all properties":      rights["RIGHT_DS_READ_PROPERTY"],
		"Write all properties":     rights["RIGHT_DS_WRITE_PROPERTY"],
		"Delete":                   rights["RIGHT_DELETE"],
		"Delete subtree":           rights["RIGHT_DS_DELETE_TREE"],
		"Read permissions":         rights["RIGHT_READ_CONTROL"],
		"Modify permissions":       rights["RIGHT_WRITE_DACL"],
		"Modify owner":             rights["RIGHT_WRITE_OWNER"],
		"All validated writes":     rights["RIGHT_DS_SELF"],
		"All extended rights":      rights["RIGHT_DS_CONTROL_ACCESS"],
		"Create all child objects": rights["RIGHT_DS_CREATE_CHILD"],
		"Delete all child objects": rights["RIGHT_DS_DELETE_CHILD"],
	}

	normalRightsVals = []string{
		"List contents", "List object", "Read all properties",
		"Write all properties", "Delete", "Delete subtree",
		"Read permissions", "Modify permissions", "Modify owner",
		"All validated writes", "All extended rights",
		"Create all child objects", "Delete all child objects",
	}
}

func loadIntoCache(source map[string]string, reverse map[string]string, values *[]string) {
	for key, val := range source {
		reverse[val] = key
		*values = append(*values, val)
	}
}

func loadSchemaVars(includeCurSchema bool) {
	if includeCurSchema {
		// Get classes and attributes
		classes, attrs, err := lc.FindSchemaClassesAndAttributes()
		if err == nil {
			for key, val := range classes {
				sdl.ClassGuids[key] = val
			}

			for key, val := range attrs {
				// Are property sets being included here?
				sdl.AttributeGuids[key] = val
			}
		}

		// Get extended rights
		extendedRights, err := lc.FindSchemaControlAccessRights("(validAccesses=256)")
		if err == nil {
			for key, val := range extendedRights {
				sdl.ExtendedGuids[key] = val
			}
		}

		// Get validated writes
		validatedWriteRights, err := lc.FindSchemaControlAccessRights("(validAccesses=8)")
		if err == nil {
			for key, val := range validatedWriteRights {
				sdl.ValidatedWriteGuids[key] = val
			}
		}
	}

	loadIntoCache(sdl.ClassGuids, revClassGuids, &classVals)
	loadIntoCache(sdl.AttributeGuids, revAttrGuids, &attributesVals)
	loadIntoCache(sdl.PropertySetGuids, revAttrGuids, &attributesVals)
	loadIntoCache(sdl.ExtendedGuids, revExtendedGuids, &extendedVals)
	loadIntoCache(sdl.ValidatedWriteGuids, revValidatedWriteRightGuids, &validatedWriteRightsVals)

	sort.Strings(classVals)
	sort.Strings(attributesVals)
	sort.Strings(extendedVals)
	sort.Strings(validatedWriteRightsVals)
}

func removeAce(aceIdx int) {
	// Remove item from ACEs list
	updatedAces := append(
		sd.DACL.Aces[:aceIdx-1],
		sd.DACL.Aces[aceIdx:]...,
	)
	sd.SetDaclACES(updatedAces)

	newSd, _ := hex.DecodeString(sd.Encode())

	err = lc.ModifyDACL(object, string(newSd))
	if err == nil {
		go app.QueueUpdateDraw(updateDaclEntries)

		updateLog("ACE deleted for object '"+object+"'", "green")

		if aceIdx > 0 {
			if aceIdx <= len(updatedAces) {
				selectDaclEntry(updatedAces[aceIdx-1])
			} else if aceIdx > 1 {
				selectDaclEntry(updatedAces[aceIdx-2])
			}
		}
	} else {
		updateLog(fmt.Sprint(err), "red")
	}
}

func getType(guid string, isAllow bool) int {
	if guid != "" {
		if isAllow {
			return 5
		} else {
			return 6
		}
	}

	if isAllow {
		return 0
	} else {
		return 1
	}
}

func getFlags(objectGuid string, inheritedGuid string) int {
	flags := 0
	if objectGuid != "" {
		flags |= 0b01
	}
	if inheritedGuid != "" {
		flags |= 0b10
	}
	return flags
}

func createOrUpdateAce(aceIdx int, newAllowOrDeny bool, newACEFlags int, newMask int, newObjectGuid string, newInheritedGuid string, newPrincipalSID string) {
	var newACEHeader *sdl.ACEHEADER = new(sdl.ACEHEADER)
	var newACE sdl.ACEInt

	newACEHeader.ACEType = fmt.Sprintf("%02x", getType(newObjectGuid, newAllowOrDeny))

	if newObjectGuid != "" {
		newACE = new(sdl.OBJECT_ACE)

		newObjectGuidEncoded, err := ldaputils.EncodeGUID(newObjectGuid)
		if err != nil {
			newObjectGuidEncoded = ""
		}
		newInheritedGuidEncoded, err := ldaputils.EncodeGUID(newInheritedGuid)
		if err != nil {
			newInheritedGuidEncoded = ""
		}

		newFlags := getFlags(newObjectGuid, newInheritedGuid)

		newACE.(*sdl.OBJECT_ACE).Flags = ldaputils.EndianConvert(fmt.Sprintf("%08x", newFlags))
		newACE.(*sdl.OBJECT_ACE).ObjectType = newObjectGuidEncoded
		newACE.(*sdl.OBJECT_ACE).InheritedObjectType = newInheritedGuidEncoded
	} else {
		newACE = new(sdl.BASIC_ACE)
	}

	newACEHeader.ACEFlags = ldaputils.EndianConvert(fmt.Sprintf("%02x", newACEFlags))

	// Set ACE Mask
	newACE.SetMask(newMask)

	// Set ACE Trustee
	newACE.SetSID(newPrincipalSID)

	// Set placeholder ACE size
	newACEHeader.AceSizeBytes = "0000"

	// Fill in the ACE Header
	newACE.SetHeader(newACEHeader)

	// Update ACE size
	aceSizeBytes := len(newACE.Encode()) / 2
	newACE.GetHeader().AceSizeBytes = ldaputils.EndianConvert(fmt.Sprintf("%04x", aceSizeBytes))

	var updatedAces []sdl.ACEInt

	if aceIdx < 0 {
		// Add the ACE to the end of the DACL
		updatedAces = append(sd.DACL.Aces, newACE)
	} else {
		// Add the ACE to the specified aceIdx
		updatedAces = append(
			sd.DACL.Aces[:aceIdx-1],
			append([]sdl.ACEInt{newACE}, sd.DACL.Aces[aceIdx:]...)...,
		)
	}

	sd.SetDaclACES(updatedAces)

	// Modify the DACL to include the new ACE
	newSd, _ := hex.DecodeString(sd.Encode())

	err = lc.ModifyDACL(object, string(newSd))

	if err == nil {
		go app.QueueUpdateDraw(updateDaclEntries)
		updateLog("DACL updated successfully!", "green")

		// Update selection
		selectDaclEntry(newACE)
	} else {
		updateLog(fmt.Sprint(err), "red")
	}
}

func loadDeleteAceForm(aceIdx int) {
	object := objectNameInputDacl.GetText()
	aceEntry := parsedAces[aceIdx-1]
	if aceEntry.Inheritance {
		updateLog("Inherited ACEs cannot be deleted.", "red")
		return
	}

	readableMask := "Special"
	if len(aceEntry.Mask) == 1 {
		readableMask = aceEntry.Mask[0]
	}

	promptModal := tview.NewModal().
		SetText("Do you really want to delete this ACE?\nObject: " + object + "\nTrustee: " + aceEntry.SamAccountName + "\nRight: " + readableMask).
		AddButtons([]string{"No", "Yes"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				ok := safetyCheck(object, sd, func(buttonIndex int, buttonLabel string) {
					if buttonIndex == 0 {
						app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
					} else {
						removeAce(aceIdx)
						app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
					}
				})

				if ok {
					removeAce(aceIdx)
					app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
				}
			} else {
				app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
			}
		})

	app.SetRoot(promptModal, true).SetFocus(promptModal)
}

// Forms
func getNormalPermsForm(mask int, checkedFull func(bool), checkedRight func(bool, int)) *tview.Form {
	form := NewXForm()

	form.AddCheckbox("Full control", false, checkedFull)

	for _, rightName := range normalRightsVals {
		rightMask := normalRights[rightName]
		curRightMask := rightMask
		form.AddCheckbox(
			rightName,
			mask&rightMask != 0,
			func(checked bool) {
				checkedRight(checked, curRightMask)
			})
	}

	return form.SetItemPadding(0)
}

func getObjectPermsForm(object int, objectRight int, selectedObject func(string, int), selectedRight func(string, int)) *tview.Form {
	form := NewXForm().
		AddDropDown("Object Class", classVals,
			object, selectedObject).
		SetFieldBackgroundColor(fieldBackgroundColor).
		AddDropDown(
			"Right", []string{"Create Child", "Delete Child", "Create & Delete Child"},
			objectRight, selectedRight).
		SetFieldBackgroundColor(fieldBackgroundColor)

	return form
}

func getPropertyPermsForm(property int, propertyRight int, selectedProperty func(string, int), selectedRight func(string, int)) *XForm {
	form := NewXForm()
	form.
		AddDropDown(
			"Property", attributesVals, property, selectedProperty).
		SetFieldBackgroundColor(fieldBackgroundColor).
		AddDropDown(
			"Right",
			[]string{"Read Property", "Write Property", "Read & Write Property"},
			propertyRight, selectedRight).
		SetFieldBackgroundColor(fieldBackgroundColor)
	return form
}

func getControlPermsForm(controlRight int, selectedRight func(string, int)) *tview.Form {
	form := NewXForm().
		AddDropDown(
			"Extended Right", extendedVals,
			controlRight, selectedRight).
		SetFieldBackgroundColor(fieldBackgroundColor)
	return form
}

func getValidatedWritePermsForm(validatedWriteRight int, selectedRight func(string, int)) *tview.Form {
	form := NewXForm().
		AddDropDown(
			"Validated Write", validatedWriteRightsVals,
			validatedWriteRight, selectedRight).
		SetFieldBackgroundColor(fieldBackgroundColor)
	return form
}

func safetyCheck(object string, sd *sdl.SecurityDescriptor, doneFunc func(int, string)) bool {
	currentSD, err := lc.GetSecurityDescriptor(object)

	if err == nil && currentSD != sd.Encode() {
		warningText := "Warning\n"
		warningText += "The DACL of this object was changed outside of Godap after your query.\n"
		warningText += "If you proceed these changes will be reverted.\n"
		warningText += "You might want to go back, rerun your query and try again."
		safetyModal := tview.NewModal().
			SetText(warningText).
			AddButtons([]string{"Go Back", "Update Anyway"}).
			SetDoneFunc(doneFunc)

		app.SetRoot(safetyModal, true).SetFocus(safetyModal)
		return false
	}

	return true
}

func updateACETypeCell(table *tview.Table, newType int) {
	table.SetCell(1, 1, tview.NewTableCell(strconv.Itoa(newType)))
}

func updateACEFlagsCell(table *tview.Table, newACEFlags int) {
	table.SetCell(2, 1, tview.NewTableCell(fmt.Sprintf("%08b", newACEFlags)))
}

func updateMaskCell(table *tview.Table, newMask int) {
	cell := tview.NewTableCell(fmt.Sprintf("%032b", newMask))
	if newMask == 0 {
		cell.SetTextColor(tcell.GetColor("red"))
	} else {
		cell.SetTextColor(tcell.GetColor("green"))
	}

	table.SetCell(3, 1, cell)
}

func updateFlagsCell(table *tview.Table, flags int) {
	table.SetCell(4, 1, tview.NewTableCell(strconv.Itoa(flags)))
}

func updateObjectGuidCell(table *tview.Table, objectGuid string) {
	table.SetCell(5, 1, tview.NewTableCell(objectGuid))
}

func updateInheritedGuidCell(table *tview.Table, inheritedGuid string) {
	table.SetCell(6, 1, tview.NewTableCell(inheritedGuid))
}

func updatePrincipalCell(table *tview.Table, principalSID string) {
	var cell *tview.TableCell
	if principalSID != "" {
		cell = tview.NewTableCell(principalSID)
		cell.SetTextColor(tcell.GetColor("green"))
	} else {
		cell = tview.NewTableCell("Not Found")
		cell.SetTextColor(tcell.GetColor("red"))
	}

	table.SetCell(7, 1, cell)
}

// Main Form
func loadAceEditorForm(aceIdx int) {
	var (
		// Core values extracted from current ACE
		valKind          int
		valType          int
		valACEFlags      int
		valMask          int
		valFlags         int
		valObjectGuid    string
		valInheritedGuid string
		valPrincipalSID  string

		// Default values for form fields
		selectedPrincipal           string
		selectedType                int
		selectedNoPropagate         bool
		selectedScope               int
		selectedObject              int
		selectedObjectRight         int
		selectedProperty            int
		selectedPropertyRight       int
		selectedControlRight        int
		selectedValidatedWriteRight int

		// New values
		newMask          int
		newObjectGuid    string
		newInheritedGuid string
		newPrincipalSID  string
		newACEFlags      int
		newAllowOrDeny   bool
	)

	// ACE preview table
	newAceTable = tview.NewTable()

	// Setting up options
	typeOptions := []string{"[green]Allow", "[red]Deny"}
	scopeOptions := []string{
		"This object only",
		"This object and all descendant objects",
		"All descendant objects",
	}

	classesIndices := make(map[string]int)
	for idx, objectClass := range classVals {
		scopeOptions = append(scopeOptions, "Descendant "+objectClass+" objects")
		classesIndices[objectClass] = idx
	}

	// Getting object name
	object := objectNameInputDacl.GetText()

	// Initial values
	if aceIdx > 0 && aceIdx < len(parsedAces) {
		aceEntry := parsedAces[aceIdx-1]
		if aceEntry.Inheritance {
			updateLog("Inherited ACEs cannot be edited.", "red")
			return
		}

		aceRaw := aceEntry.Raw
		aceHeader := aceRaw.GetHeader()

		// ACE Trustee
		valPrincipalSID = aceRaw.GetSID()
		selectedPrincipal = aceEntry.SamAccountName

		// ACE Type
		valType = ldaputils.HexToInt(aceHeader.ACEType)
		if valType == 0 || valType == 5 {
			selectedType = 0
		} else {
			selectedType = 1
		}

		// ACE Mask
		valMask = aceEntry.Raw.GetMask()
		newMask = valMask

		switch aceRaw.(type) {
		case *sdl.OBJECT_ACE:
			valObjectGuid, valInheritedGuid = aceRaw.(*sdl.OBJECT_ACE).GetObjectAndInheritedType()

			if valObjectGuid != "" {
				if valMask&0b110000 != 0 { // Property right
					valKind = 2
				} else if valMask&0b100000000 != 0 { // Extended right
					valKind = 3
				} else if valMask&0b11 != 0 { // Object right
					valKind = 1
				} else if valMask&0b1000 != 0 {
					valKind = 4
				} else {
					// Should never happen (???)
				}
			}
		}

		// Flags
		valFlags = getFlags(valObjectGuid, valInheritedGuid)

		// ACE Scope
		valACEFlags = ldaputils.HexToInt(aceHeader.ACEFlags)
		newACEFlags = valACEFlags

		if valACEFlags&sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"] != 0 {
			selectedNoPropagate = true
		}

		if valACEFlags&sdl.AceFlagsMap["CONTAINER_INHERIT_ACE"] != 0 {
			if valACEFlags&sdl.AceFlagsMap["INHERIT_ONLY_ACE"] == 0 {
				selectedScope = 1
			} else {
				if valInheritedGuid == "" {
					selectedScope = 2
				} else {
					selectedScope = 3 + classesIndices[sdl.ClassGuids[valInheritedGuid]]
				}
			}
		}

		switch valKind {
		case 1:
			// Object
			selectedObject = ldaputils.IndexOf(classVals, sdl.ClassGuids[valObjectGuid])
			if valMask&rights["RIGHT_DS_CREATE_CHILD"] != 0 {
				selectedObjectRight = 0
				if valMask&rights["RIGHT_DS_DELETE_CHILD"] != 0 {
					selectedObjectRight = 2
				}
			} else if valMask&rights["RIGHT_DS_DELETE_CHILD"] != 0 {
				selectedObjectRight = 1
			}
		case 2:
			// Property
			propertyName, ok := sdl.AttributeGuids[valObjectGuid]
			if !ok {
				propertyName, ok = sdl.PropertySetGuids[valObjectGuid]
			}

			selectedProperty = ldaputils.IndexOf(attributesVals, propertyName)
			if newMask&rights["RIGHT_DS_READ_PROPERTY"] != 0 {
				selectedPropertyRight = 0
				if newMask&rights["RIGHT_DS_WRITE_PROPERTY"] != 0 {
					selectedPropertyRight = 2
				}
			} else if newMask&rights["RIGHT_DS_WRITE_PROPERTY"] != 0 {
				selectedPropertyRight = 1
			}
		case 3:
			selectedControlRight = ldaputils.IndexOf(
				extendedVals,
				sdl.ExtendedGuids[valObjectGuid],
			)
		case 4:
			selectedValidatedWriteRight = ldaputils.IndexOf(
				validatedWriteRightsVals, sdl.ValidatedWriteGuids[valObjectGuid],
			)
		}
	}

	aceEditorHeader := tview.NewFlex()

	permsPanel = tview.NewFlex().SetDirection(tview.FlexRow)
	permsPanel.
		SetTitle("Permissions").
		SetBorder(true)

	headerForm := NewXForm()
	headerForm.
		AddDropDown(
			"ACE Kind",
			[]string{"Normal", "Object", "Property", "Extended", "Validated Write"},
			valKind, func(option string, optionIdx int) {
				permsPanel.Clear()

				switch optionIdx {
				case 0:
					newObjectGuid = ""
					updateObjectGuidCell(newAceTable, newObjectGuid)
					updateFlagsCell(newAceTable, getFlags(newObjectGuid, newInheritedGuid))

					newMask = 0
					if valKind == 0 {
						newMask = valMask
					}
					updateMaskCell(newAceTable, newMask)

					normalPermsForm = getNormalPermsForm(
						newMask,
						func(checked bool) {
							// Using the GA flag is going to include all normal rights
							// by setting a single bit. Therefore the Full Control checkbox
							// is always going to be unchecked unless explicitly toggled.
							if checked {
								newMask |= 0x10000000
							} else {
								newMask &^= 0x10000000
							}

							updateMaskCell(newAceTable, newMask)
						},
						func(checked bool, mask int) {
							if checked {
								newMask |= mask
							} else {
								newMask &^= mask
							}

							updateMaskCell(newAceTable, newMask)
						})

					permsPanel.AddItem(normalPermsForm, 0, 1, false)
				case 1:
					// Object
					objectPermsForm = getObjectPermsForm(
						selectedObject,
						selectedObjectRight,
						func(option string, optionIdx int) {
							newObjectGuid = revClassGuids[option]
							updateObjectGuidCell(newAceTable, newObjectGuid)
							updateFlagsCell(newAceTable, getFlags(newObjectGuid, newInheritedGuid))
						},
						func(option string, optionIdx int) {
							switch optionIdx {
							case 0:
								newMask = rights["RIGHT_DS_CREATE_CHILD"]
							case 1:
								newMask = rights["RIGHT_DS_DELETE_CHILD"]
							case 2:
								newMask = rights["RIGHT_DS_CREATE_CHILD"]
								newMask |= rights["RIGHT_DS_DELETE_CHILD"]
							}

							updateMaskCell(newAceTable, newMask)
						})

					permsPanel.AddItem(objectPermsForm, 0, 1, false)
				case 2:
					// Property
					propertyPermsForm = getPropertyPermsForm(
						selectedProperty,
						selectedPropertyRight,
						func(option string, optionIdx int) {
							newObjectGuid = revAttrGuids[option]
							updateObjectGuidCell(newAceTable, newObjectGuid)
							updateFlagsCell(newAceTable, getFlags(newObjectGuid, newInheritedGuid))
						},
						func(option string, optionIdx int) {
							rightRead := rights["RIGHT_DS_READ_PROPERTY"]
							rightWrite := rights["RIGHT_DS_WRITE_PROPERTY"]
							switch optionIdx {
							case 0:
								newMask = rightRead
							case 1:
								newMask = rightWrite
							case 2:
								newMask = rightRead | rightWrite
							}

							updateMaskCell(newAceTable, newMask)
						})
					permsPanel.AddItem(propertyPermsForm, 0, 1, false)
				case 3:
					// Extended
					newMask = rights["RIGHT_DS_CONTROL_ACCESS"]
					updateMaskCell(newAceTable, newMask)

					controlPermsForm = getControlPermsForm(
						selectedControlRight,
						func(option string, optionIdx int) {
							newObjectGuid = revExtendedGuids[option]
							newMask = rights["RIGHT_DS_CONTROL_ACCESS"]

							updateObjectGuidCell(newAceTable, newObjectGuid)
							updateFlagsCell(newAceTable, getFlags(newObjectGuid, newInheritedGuid))
							updateMaskCell(newAceTable, newMask)
						})
					permsPanel.AddItem(controlPermsForm, 0, 1, false)
				case 4:
					// Validated Write
					newMask = rights["RIGHT_DS_SELF"]
					updateMaskCell(newAceTable, newMask)

					validatedWritePermsForm = getValidatedWritePermsForm(
						selectedValidatedWriteRight,
						func(option string, optionIdx int) {
							newObjectGuid = revValidatedWriteRightGuids[option]
							newMask = rights["RIGHT_DS_SELF"]

							updateObjectGuidCell(newAceTable, newObjectGuid)
							updateFlagsCell(newAceTable, getFlags(newObjectGuid, newInheritedGuid))
							updateMaskCell(newAceTable, newMask)
						})
					permsPanel.AddItem(validatedWritePermsForm, 0, 1, false)
				}

				updateACETypeCell(newAceTable, getType(newObjectGuid, newAllowOrDeny))
			}).
		AddInputField("Principal", selectedPrincipal, 0, nil, nil).
		AddDropDown("Type", typeOptions, selectedType,
			func(option string, optionIdx int) {
				newAllowOrDeny = (optionIdx == 0)
				updateACETypeCell(newAceTable, getType(newObjectGuid, newAllowOrDeny))
			}).
		AddCheckbox("No Propagate", selectedNoPropagate, func(checked bool) {
			if checked {
				newACEFlags |= sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"]
			} else {
				newACEFlags &^= sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"]
			}

			updateACEFlagsCell(newAceTable, newACEFlags)
		})

	headerForm.
		AddDropDown("Applies to", scopeOptions, selectedScope,
			func(option string, optionIdx int) {
				noPropagateMask := 0b00000000
				if newACEFlags&sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"] != 0 {
					noPropagateMask = sdl.AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"]
				}

				switch optionIdx {
				case 0:
					newInheritedGuid = ""
					newACEFlags &^= 0b11111111
					headerForm.GetFormItemByLabel("No Propagate").(*tview.Checkbox).SetDisabled(true)
					headerForm.GetFormItemByLabel("No Propagate").(*tview.Checkbox).SetChecked(false)
				case 1:
					newInheritedGuid = ""
					newACEFlags |= 0b00000010
					newACEFlags &^= 0b00001000
					headerForm.GetFormItemByLabel("No Propagate").(*tview.Checkbox).SetDisabled(false)
				case 2:
					newInheritedGuid = ""
					newACEFlags = 0b00001010 | noPropagateMask
					headerForm.GetFormItemByLabel("No Propagate").(*tview.Checkbox).SetDisabled(false)
				default:
					newInheritedGuid = revClassGuids[classVals[optionIdx-3]]
					newACEFlags = 0b00001010 | noPropagateMask
					headerForm.GetFormItemByLabel("No Propagate").(*tview.Checkbox).SetDisabled(false)
				}

				updateInheritedGuidCell(newAceTable, newInheritedGuid)
				updateFlagsCell(newAceTable, getFlags(newObjectGuid, newInheritedGuid))
				updateACEFlagsCell(newAceTable, newACEFlags)
			}).
		SetFieldBackgroundColor(fieldBackgroundColor)

	headerForm.
		SetItemPadding(0).
		SetTitle("Options").
		SetBorder(true)

	principalFormItem := headerForm.GetFormItemByLabel("Principal")
	updatePrincipalSIDField := func() {
		var err error

		principal := principalFormItem.(*tview.InputField).GetText()

		newPrincipalSID, err = lc.FindSIDForObject(principal)

		if err == nil {
			updatePrincipalCell(newAceTable, newPrincipalSID)
		} else {
			if ldaputils.IsSID(principal) {
				newPrincipalSID = principal
			} else {
				newPrincipalSID = ""
			}

			updatePrincipalCell(newAceTable, newPrincipalSID)
		}
	}

	updatePrincipalSIDField()

	principalFormItem.(*tview.InputField).
		SetDoneFunc(func(key tcell.Key) { updatePrincipalSIDField() })

	aceEditorHeader.AddItem(headerForm, 0, 1, false)

	// Bottom Buttons
	updateBtnText := "Update"
	if aceIdx < 0 {
		updateBtnText = "Create"
	}

	updateBtn := tview.NewButton(updateBtnText).SetSelectedFunc(func() {
		if newMask == 0 || newPrincipalSID == "" {
			validationModal := tview.NewModal().
				SetText("You must set a valid principal and a non-zero mask!").
				AddButtons([]string{"Ok"}).
				SetDoneFunc(func(buttonIndex int, buttonLabel string) {
					app.SetRoot(aceEditorPage, true).SetFocus(aceEditorPage)
				})
			app.SetRoot(validationModal, true).SetFocus(validationModal)
			return
		}

		ok := safetyCheck(object, sd, func(buttonIndex int, buttonLabel string) {
			if buttonIndex == 0 {
				app.SetRoot(aceEditorPage, true).SetFocus(aceEditorPage)
			} else {
				createOrUpdateAce(
					aceIdx, newAllowOrDeny, newACEFlags,
					newMask, newObjectGuid, newInheritedGuid,
					newPrincipalSID,
				)
				app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
			}
		})

		if ok {
			createOrUpdateAce(
				aceIdx, newAllowOrDeny, newACEFlags,
				newMask, newObjectGuid, newInheritedGuid,
				newPrincipalSID,
			)
			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
		}
	})
	assignButtonTheme(updateBtn)

	cancelBtn := tview.NewButton("Go Back").SetSelectedFunc(func() {
		app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
	})
	assignButtonTheme(cancelBtn)

	currentAceTable := tview.NewTable().
		SetBorders(false).
		SetCell(0, 0, tview.NewTableCell("Field").SetAlign(tview.AlignCenter)).
		SetCell(0, 1, tview.NewTableCell("Value").SetAlign(tview.AlignCenter))

	currentAceTable.SetCell(1, 0, tview.NewTableCell("Type"))
	currentAceTable.SetCell(2, 0, tview.NewTableCell("ACEFlags"))
	currentAceTable.SetCell(3, 0, tview.NewTableCell("Mask"))
	currentAceTable.SetCell(4, 0, tview.NewTableCell("Flags"))
	currentAceTable.SetCell(5, 0, tview.NewTableCell("ObjType"))
	currentAceTable.SetCell(6, 0, tview.NewTableCell("InhType"))
	currentAceTable.SetCell(7, 0, tview.NewTableCell("Trustee"))

	currentAceTable.SetCell(1, 1, tview.NewTableCell(strconv.Itoa(valType)))
	currentAceTable.SetCell(2, 1, tview.NewTableCell(strconv.Itoa(valACEFlags)))
	currentAceTable.SetCell(3, 1, tview.NewTableCell(strconv.Itoa(valMask)))
	currentAceTable.SetCell(4, 1, tview.NewTableCell(strconv.Itoa(valFlags)))
	currentAceTable.SetCell(5, 1, tview.NewTableCell(valObjectGuid))
	currentAceTable.SetCell(6, 1, tview.NewTableCell(valInheritedGuid))
	currentAceTable.SetCell(7, 1, tview.NewTableCell(valPrincipalSID))

	currentAceTable.
		SetTitle("Current ACE").
		SetBorder(true)

	updateACETypeCell(currentAceTable, valType)
	updateACEFlagsCell(currentAceTable, valACEFlags)
	updateMaskCell(currentAceTable, valMask)
	updateFlagsCell(currentAceTable, valFlags)
	updateObjectGuidCell(currentAceTable, valObjectGuid)
	updateInheritedGuidCell(currentAceTable, valInheritedGuid)
	updatePrincipalCell(currentAceTable, valPrincipalSID)

	// ACE Editor Page
	aceEditorPage = tview.NewFlex().SetDirection(tview.FlexColumn)
	aceEditorPage.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(daclEntriesPanel)
			return nil
		}
		return event
	})

	aceEditorPage.
		SetBorder(true).
		SetTitle("ACE Editor (" + object + ")")

	newAceTable.
		SetBorders(false).
		SetCell(0, 0, tview.NewTableCell("Field").SetAlign(tview.AlignCenter)).
		SetCell(0, 1, tview.NewTableCell("Value").SetAlign(tview.AlignCenter))

	newAceTable.SetCell(1, 0, tview.NewTableCell("Type"))
	newAceTable.SetCell(2, 0, tview.NewTableCell("ACEFlags"))
	newAceTable.SetCell(3, 0, tview.NewTableCell("Mask"))
	newAceTable.SetCell(4, 0, tview.NewTableCell("Flags"))
	newAceTable.SetCell(5, 0, tview.NewTableCell("ObjType"))
	newAceTable.SetCell(6, 0, tview.NewTableCell("InhType"))
	newAceTable.SetCell(7, 0, tview.NewTableCell("Trustee"))
	newAceTable.
		SetTitle("New ACE").
		SetBorder(true)

	computedPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(currentAceTable, 0, 1, false).
		AddItem(newAceTable, 0, 1, false).
		AddItem(
			tview.NewFlex().
				AddItem(tview.NewBox(), 1, 0, false). // Spacing
				AddItem(cancelBtn, 10, 0, false).
				AddItem(tview.NewBox(), 0, 1, false). // Spacing
				AddItem(updateBtn, 10, 0, false).
				AddItem(tview.NewBox(), 1, 0, false), // Spacing
			1, 0, false)

	computedPanel.
		SetBorder(true)

	aceEditorPage.
		AddItem(
			tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(aceEditorHeader, 9, 1, true).
				AddItem(permsPanel, 0, 1, false),
			0, 1, false).
		AddItem(computedPanel, 0, 1, false)
	app.SetRoot(aceEditorPage, true).SetFocus(aceEditorPage)
}
