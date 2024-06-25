package sdl

//ldaputils.HexToInt(ace.Header.ACEFlags)
import (
	"fmt"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
)

// ACE Header
type ACEHEADER struct {
	ACEType      string
	ACEFlags     string
	AceSizeBytes string
}

func newACEHeader(SD string) *ACEHEADER {
	ACEHeader := new(ACEHEADER)
	ACEHeader.ACEType = SD[0:2]
	ACEHeader.ACEFlags = SD[2:4]
	ACEHeader.AceSizeBytes = SD[4:8]

	return ACEHeader
}

func (ah *ACEHEADER) Encode() string {
	return ah.ACEType + ah.ACEFlags + ah.AceSizeBytes
}

// ACE Interface
type ACEInt interface {
	GetHeader() *ACEHEADER
	GetMask() int
	GetSID() string
	SetHeader(*ACEHEADER)
	SetMask(int)
	SetSID(string) error
	Parse(string)
	Encode() string
}

// Basic ACE (embedded in more advanced types)
type BASIC_ACE struct {
	Header *ACEHEADER
	Mask   string
	SID    string
}

func (ace *BASIC_ACE) GetHeader() *ACEHEADER {
	return ace.Header
}

func (ace *BASIC_ACE) GetMask() int {
	return ldaputils.HexToInt(ldaputils.EndianConvert(ace.Mask))
}

func (ace *BASIC_ACE) GetSID() string {
	return ldaputils.ConvertSID(ace.SID)
}

func (ace *BASIC_ACE) SetHeader(header *ACEHEADER) {
	ace.Header = header
}

func (ace *BASIC_ACE) SetMask(mask int) {
	ace.Mask = ldaputils.EndianConvert(fmt.Sprintf("%08x", mask))
}

func (ace *BASIC_ACE) SetSID(sid string) error {
	encodedSid, err := ldaputils.EncodeSID(sid)

	if err == nil {
		ace.SID = encodedSid
	}

	return err
}

func (ace *BASIC_ACE) Parse(rawACE string) {
	ace.Header = newACEHeader(rawACE)
	ace.Mask = rawACE[8:16]
	ace.SID = rawACE[16:]
}

func (ace *BASIC_ACE) Encode() string {
	var s string
	s = ace.Header.Encode()
	s += ace.Mask
	s += ace.SID
	return s
}

// Object ACE (base type embedded in more advanced types)
type OBJECT_ACE struct {
	BASIC_ACE
	Flags               string
	ObjectType          string
	InheritedObjectType string
}

func (ace *OBJECT_ACE) Parse(rawACE string) {
	ace.Header = newACEHeader(rawACE)
	ace.Mask = rawACE[8:16]
	ace.Flags = rawACE[16:24]

	ace.ObjectType = ""
	ace.InheritedObjectType = ""

	switch ldaputils.EndianConvert(ace.Flags) {
	case "00000001":
		ace.ObjectType = rawACE[24:56]
	case "00000002":
		ace.InheritedObjectType = rawACE[24:56]
	case "00000003":
		ace.ObjectType = rawACE[24:56]
		ace.InheritedObjectType = rawACE[56:88]
	}

	lengthBeforeSID := 24
	if len(ace.ObjectType) > 0 {
		lengthBeforeSID += 32
	}
	if len(ace.InheritedObjectType) > 0 {
		lengthBeforeSID += 32
	}
	ace.SID = rawACE[lengthBeforeSID:]
}

func (ace *OBJECT_ACE) Encode() string {
	var s string
	s = ace.Header.Encode()
	s += ace.Mask
	s += ace.Flags
	s += ace.ObjectType
	s += ace.InheritedObjectType
	s += ace.SID

	return s
}

func (ace *OBJECT_ACE) GetObjectAndInheritedType() (objectTypeGUID string, inheritedObjectTypeGUID string) {
	switch ldaputils.EndianConvert(ace.Flags) {
	case "00000001":
		objectTypeGUID = ldaputils.ConvertGUID(ace.ObjectType)
		inheritedObjectTypeGUID = ""
	case "00000002":
		inheritedObjectTypeGUID = ldaputils.ConvertGUID(ace.InheritedObjectType)
		objectTypeGUID = ""
	case "00000003":
		objectTypeGUID = ldaputils.ConvertGUID(ace.ObjectType)
		inheritedObjectTypeGUID = ldaputils.ConvertGUID(ace.InheritedObjectType)
	}

	return
}

// Placeholder type for ACES that were not implemented
// They should be kept "as-is" when parsing
type NOTIMPL_ACE struct {
	BASIC_ACE
	rawHex string
}

func (ace *NOTIMPL_ACE) Parse(rawACE string) {
	ace.rawHex = rawACE
}

func (ace *NOTIMPL_ACE) Encode() string {
	return ace.rawHex
}

// Specific definitions
type ACCESS_ALLOWED_ACE struct {
	BASIC_ACE
}

type ACCESS_DENIED_ACE struct {
	BASIC_ACE
}

type ACCESS_ALLOWED_OBJECT_ACE struct {
	OBJECT_ACE
}

type ACCESS_DENIED_OBJECT_ACE struct {
	OBJECT_ACE
}

// The ACE types below seem currently useless,
// if I figure out any use for them in the future I'll
// consider implementing some additional logic

/*
// Callback Types
type ACCESS_ALLOWED_CALLBACK_ACE struct {
	BASIC_ACE
	applicationData string
}

type ACCESS_DENIED_CALLBACK_ACE struct {
	BASIC_ACE
	applicationData string
}

type ACCESS_ALLOWED_CALLBACK_OBJECT_ACE struct {
	OBJECT_ACE
	applicationData string
}

type ACCESS_DENIED_CALLBACK_OBJECT_ACE struct {
	OBJECT_ACE
	applicationData string
}

// SACL Types
type SYSTEM_AUDIT_ACE struct {
	BASIC_ACE
}

type SYSTEM_AUDIT_OBJECT_ACE struct {
	OBJECT_ACE
	applicationData string
}

type SYSTEM_AUDIT_CALLBACK_ACE struct {
	BASIC_ACE
	applicationData string
}

type SYSTEM_AUDIT_CALLBACK_OBJECT_ACE struct {
	OBJECT_ACE
	applicationData string
}

type SYSTEM_MANDATORY_LABEL_ACE struct {
	BASIC_ACE
}

type SYSTEM_RESOURCE_ATTRIBUTE_ACE struct {
	BASIC_ACE
	attributeData string
}

type SYSTEM_SCOPED_POLICY_ID_ACE struct {
	BASIC_ACE
}
*/
