package adidns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Helper values
var DnsRecordTypes map[uint16]string = map[uint16]string{
	0x0000: "ZERO",
	0x0001: "A",
	0x0002: "NS",
	0x0003: "MD",
	0x0004: "MF",
	0x0005: "CNAME",
	0x0006: "SOA",
	0x0007: "MB",
	0x0008: "MG",
	0x0009: "MR",
	0x000A: "NULL",
	0x000B: "WKS",
	0x000C: "PTR",
	0x000D: "HINFO",
	0x000E: "MINFO",
	0x000F: "MX",
	0x0010: "TXT",
	0x0011: "RP",
	0x0012: "AFSDB",
	0x0013: "X25",
	0x0014: "ISDN",
	0x0015: "RT",
	0x0018: "SIG",
	0x0019: "KEY",
	0x001C: "AAAA",
	0x001D: "LOC",
	0x001E: "NXT",
	0x0021: "SRV",
	0x0022: "ATMA",
	0x0023: "NAPTR",
	0x0027: "DNAME",
	0x002B: "DS",
	0x002E: "RRSIG",
	0x002F: "NSEC",
	0x0030: "DNSKEY",
	0x0031: "DHCID",
	0x0032: "NSEC3",
	0x0033: "NSEC3PARAM",
	0x0034: "TLSA",
	0x00FF: "ALL",
	0xFF01: "WINS",
	0xFF02: "WINSR",
}

func FindRecordType(rTypeStr string) uint16 {
	for key, val := range DnsRecordTypes {
		if rTypeStr == val {
			return uint16(key)
		}
	}

	return 0
}

type DcPromoFlag struct {
	Value       uint32
	Description string
}

var dcPromoFlags = []DcPromoFlag{
	{0x00000000, "No change to existing zone storage."},
	{0x00000001, "Zone is to be moved to the DNS domain partition."},
	{0x00000002, "Zone is to be moved to the DNS forest partition."},
}

func FindDcPromoDescription(value uint32) string {
	for _, flag := range dcPromoFlags {
		if flag.Value == value {
			return flag.Description
		}
	}
	return "Unknown DcPromo flag"
}

type DNSPropertyId struct {
	Id   uint32
	Name string
}

var DnsPropertyIds = []DNSPropertyId{
	{0x00000001, "TYPE"},
	{0x00000002, "ALLOW_UPDATE"},
	{0x00000008, "SECURE_TIME"},
	{0x00000010, "NOREFRESH_INTERVAL"},
	{0x00000020, "REFRESH_INTERVAL"},
	{0x00000040, "AGING_STATE"},
	{0x00000011, "SCAVENGING_SERVERS"},
	{0x00000012, "AGING_ENABLED_TIME"},
	{0x00000080, "DELETED_FROM_HOSTNAME"},
	{0x00000081, "MASTER_SERVERS"},
	{0x00000082, "AUTO_NS_SERVERS"},
	{0x00000083, "DCPROMO_CONVERT"},
	{0x00000090, "SCAVENGING_SERVERS_DA"},
	{0x00000091, "MASTER_SERVERS_DA"},
	{0x00000092, "AUTO_NS_SERVERS_DA"},
	{0x00000100, "NODE_DBFLAGS"},
}

func FindPropName(id uint32) string {
	for _, propertyId := range DnsPropertyIds {
		if propertyId.Id == id {
			return propertyId.Name
		}
	}
	return "UNKNOWN"
}

// ADIDNS Structures
type DNSRecord struct {
	DataLength uint16
	Type       uint16
	Version    uint8
	Rank       uint8
	Flags      uint16
	Serial     uint32
	TTLSeconds uint32
	Reserved   uint32
	Timestamp  uint32
	Data       []byte
}

func MakeDNSRecord(rec RecordData, recType uint16, ttl uint32) DNSRecord {
	serial := uint32(1)
	msTime := GetCurrentMSTime()
	data := rec.Encode()

	return DNSRecord{
		uint16(len(data)), recType,
		0x05, 0xF0,
		0x0000,
		serial, ttl,
		0x00000000,
		msTime, data,
	}
}

type DNSProperty struct {
	DataLength uint32
	NameLength uint32
	Flag       uint32
	Version    uint32
	Id         uint32
	Data       []byte
	Name       uint8
}

func MakeProp(id uint32, data []byte) DNSProperty {
	return DNSProperty{
		uint32(len(data)),
		1, 0, 1,
		id, data,
		0,
	}
}

func (prop *DNSProperty) ExportFormat() any {
	var propDataArr [8]byte
	copy(propDataArr[:], prop.Data)
	propVal := binary.LittleEndian.Uint64(propDataArr[:])

	switch prop.Id {
	case 0x01, 0x02, 0x10, 0x20, 0x40, 0x83:
		// DSPROPERTY_ZONE_TYPE
		// DSPROPERTY_ZONE_ALLOW_UPDATE
		// DSPROPERTY_ZONE_NOREFRESH_INTERVAL
		// DSPROPERTY_ZONE_REFRESH_INTERVAL
		// DSPROPERTY_ZONE_AGING_STATE
		// DSPROPERTY_ZONE_DCPROMO_CONVERT
		return propVal
	case 0x00000008:
		unixTimestamp := MSTimeToUnixTimestamp(propVal)
		return unixTimestamp
	case 0x00000012:
		// DSPROPERTY_ZONE_AGING_ENABLED_TIME
		msTime := propVal * 3600
		unixTimestamp := MSTimeToUnixTimestamp(msTime)
		return unixTimestamp
	case 0x00000080:
		// DSPROPERTY_ZONE_DELETED_FROM_HOSTNAME
		return string(prop.Data[:])
	case 0x00000090, 0x00000091, 0x00000092:
		// DSPROPERTY_ZONE_SCAVENGING_SERVERS_DA
		// DSPROPERTY_ZONE_MASTER_SERVERS_DA
		// DSPROPERTY_ZONE_AUTO_NS_SERVERS_DA
		return ParseAddrArray(prop.Data)
	case 0x00000082, 0x00000011:
		// DSPROPERTY_ZONE_SCAVENGING_SERVERS
		// DSPROPERTY_ZONE_AUTO_NS_SERVERS
		return ParseIP4Array(prop.Data)
	default:
		// DSPROPERTY_ZONE_NODE_DBFLAGS
		// Or other unknown codes
		return prop.Data
	}
}

func (prop *DNSProperty) PrintFormat(timeFormat string) string {
	var propDataArr [8]byte
	copy(propDataArr[:], prop.Data)
	propVal := binary.LittleEndian.Uint64(propDataArr[:])

	switch prop.Id {
	case 0x00000001:
		// DSPROPERTY_ZONE_TYPE
		switch propVal {
		case 0:
			return "CACHE"
		case 1:
			return "PRIMARY"
		case 2:
			return "SECONDARY"
		case 3:
			return "STUB"
		case 4:
			return "FORWARDER"
		case 5:
			return "SECONDARY_CACHE"
		default:
			return "UNKNOWN"
		}
	case 0x00000002:
		// DSPROPERTY_ZONE_ALLOW_UPDATE
		switch propVal {
		case 0:
			return "None"
		case 1:
			return "Nonsecure and secure"
		case 2:
			return "Secure only"
		default:
			return "Unknown"
		}
	case 0x00000008:
		unixTimestamp := MSTimeToUnixTimestamp(propVal)

		if unixTimestamp != -1 {
			timeObj := time.Unix(unixTimestamp, 0)
			return timeObj.Format(timeFormat)
		} else {
			return "Not specified"
		}
	case 0x00000010, 0x00000020:
		// DSPROPERTY_ZONE_NOREFRESH_INTERVAL
		// DSPROPERTY_ZONE_REFRESH_INTERVAL
		return FormatHours(propVal)
	case 0x00000012:
		// DSPROPERTY_ZONE_AGING_ENABLED_TIME
		msTime := propVal * 3600
		unixTimestamp := MSTimeToUnixTimestamp(msTime)

		if unixTimestamp != -1 {
			timeObj := time.Unix(unixTimestamp, 0)
			return timeObj.Format(timeFormat)
		} else {
			return "Not specified"
		}
	case 0x00000080:
		// DSPROPERTY_ZONE_DELETED_FROM_HOSTNAME
		return string(prop.Data[:])
	case 0x00000040:
		// DSPROPERTY_ZONE_AGING_STATE
		if propVal == 1 {
			return "Enabled"
		} else {
			return "Disabled"
		}
	case 0x00000090, 0x00000091, 0x00000092:
		// DSPROPERTY_ZONE_SCAVENGING_SERVERS_DA
		// DSPROPERTY_ZONE_MASTER_SERVERS_DA
		// DSPROPERTY_ZONE_AUTO_NS_SERVERS_DA
		return fmt.Sprintf("%v", ParseAddrArray(prop.Data))
	case 0x00000083:
		// DSPROPERTY_ZONE_DCPROMO_CONVERT
		switch propVal {
		case 0:
			return "No change"
		case 1:
			return "Move to DNS domain partition"
		case 2:
			return "Move to DNS forest partition"
		default:
			return "Unknown"
		}
	case 0x00000082, 0x00000011:
		// DSPROPERTY_ZONE_SCAVENGING_SERVERS
		// DSPROPERTY_ZONE_AUTO_NS_SERVERS
		return fmt.Sprintf("%v", ParseIP4Array(prop.Data))
	default:
		// DSPROPERTY_ZONE_NODE_DBFLAGS
		// Or other unknown codes
		return fmt.Sprintf("%v", prop.Data)
	}
}

type DNSZone struct {
	DN    string
	Name  string
	Props []DNSProperty
}

type DNSNode struct {
	DN      string
	Name    string
	Records []DNSRecord
}

func (d *DNSRecord) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, d.DataLength); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Rank); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Flags); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Serial); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, d.TTLSeconds); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Reserved); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, d.Data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *DNSRecord) Decode(data []byte) error {
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &d.DataLength); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Type); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Version); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Rank); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Flags); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Serial); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &d.TTLSeconds); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Reserved); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Timestamp); err != nil {
		return err
	}
	d.Data = make([]byte, d.DataLength)
	if err := binary.Read(buf, binary.LittleEndian, &d.Data); err != nil {
		return err
	}
	return nil
}

func (d *DNSRecord) PrintType() string {
	recordType, found := DnsRecordTypes[d.Type]
	if !found {
		recordType = "Unknown"
	}

	return recordType
}

func (r *DNSRecord) GetRecordData() RecordData {
	var parsedRecord RecordData

	switch r.Type {
	case 0x0000:
		parsedRecord = new(ZERORecord)
	case 0x0001:
		parsedRecord = new(ARecord)
	case 0x0002:
		parsedRecord = new(NSRecord)
	case 0x0003:
		parsedRecord = new(MDRecord)
	case 0x0004:
		parsedRecord = new(MFRecord)
	case 0x0005:
		parsedRecord = new(CNAMERecord)
	case 0x0006:
		parsedRecord = new(SOARecord)
	case 0x0007:
		parsedRecord = new(MBRecord)
	case 0x0008:
		parsedRecord = new(MGRecord)
	case 0x0009:
		parsedRecord = new(MRRecord)
	case 0x000A:
		parsedRecord = new(NULLRecord)
	case 0x000B:
		parsedRecord = new(WKSRecord)
	case 0x000C:
		parsedRecord = new(PTRRecord)
	case 0x000D:
		parsedRecord = new(HINFORecord)
	case 0x000E:
		parsedRecord = new(MINFORecord)
	case 0x000F:
		parsedRecord = new(MXRecord)
	case 0x0010:
		parsedRecord = new(TXTRecord)
	case 0x0011:
		parsedRecord = new(RPRecord)
	case 0x0012:
		parsedRecord = new(AFSDBRecord)
	case 0x0013:
		parsedRecord = new(X25Record)
	case 0x0014:
		parsedRecord = new(ISDNRecord)
	case 0x0015:
		parsedRecord = new(RTRecord)
	case 0x0018:
		parsedRecord = new(SIGRecord)
	case 0x0019:
		parsedRecord = new(KEYRecord)
	case 0x001C:
		parsedRecord = new(AAAARecord)
	case 0x001D:
		parsedRecord = new(LOCRecord)
	case 0x001E:
		parsedRecord = new(NXTRecord)
	case 0x0021:
		parsedRecord = new(SRVRecord)
	case 0x0022:
		parsedRecord = new(ATMARecord)
	case 0x0023:
		parsedRecord = new(NAPTRRecord)
	case 0x0027:
		parsedRecord = new(DNAMERecord)
	case 0x002B:
		parsedRecord = new(DSRecord)
	case 0x002E:
		parsedRecord = new(RRSIGRecord)
	case 0x002F:
		parsedRecord = new(NSECRecord)
	case 0x0030:
		parsedRecord = new(DNSKEYRecord)
	case 0x0031:
		parsedRecord = new(DHCIDRecord)
	case 0x0032:
		parsedRecord = new(NSEC3Record)
	case 0x0033:
		parsedRecord = new(NSEC3PARAMRecord)
	case 0x0034:
		parsedRecord = new(TLSARecord)
	case 0xFF01:
		parsedRecord = new(WINSRecord)
	case 0xFF02:
		parsedRecord = new(WINSRRecord)
	default:
		parsedRecord = new(ZERORecord)
	}
	parsedRecord.Parse(r.Data)
	return parsedRecord
}

func (d *DNSRecord) UnixTimestamp() int64 {
	msTime := uint64(d.Timestamp) * 3600
	return MSTimeToUnixTimestamp(msTime)
}

// DNS_RPC_NAME parser
func ParseRpcName(buf *bytes.Reader) (string, error) {
	var nameLen uint8

	nameLen, err := buf.ReadByte()
	if err != nil {
		return "", err
	}

	nameBuf := make([]byte, nameLen)
	if err := binary.Read(buf, binary.LittleEndian, &nameBuf); err != nil {
		return "", err
	}

	return string(nameBuf[:]), nil
}

func ParseRpcNameSingle(data []byte) (string, error) {
	buf := bytes.NewReader(data)
	return ParseRpcName(buf)
}

func EncodeRpcName(buf *bytes.Buffer, name string) {
	buf.WriteByte(byte(len(name)))
	buf.Write([]byte(name))
}

// DNS_COUNT_NAME parser
func ParseCountName(buf *bytes.Reader) (string, error) {
	var labelCnt uint8
	var labLen uint8
	var err error

	_, err = buf.ReadByte()
	if err != nil {
		return "", err
	}

	labelCnt, err = buf.ReadByte()
	if err != nil {
		return "", err
	}

	labels := make([]string, labelCnt)

	for cnt := uint8(0); cnt < labelCnt; cnt += 1 {
		labLen, err = buf.ReadByte()
		if err != nil {
			return "", err
		}

		labBuf := make([]byte, labLen)
		if _, err := io.ReadFull(buf, labBuf); err != nil {
			return "", err
		}

		labels[cnt] = string(labBuf)
	}

	// Consume the NULL terminator
	buf.ReadByte()

	return strings.Join(labels, "."), nil
}

func EncodeCountName(buf *bytes.Buffer, name string) error {
	labels := strings.Split(name, ".")

	rawNameLen := uint8(len(name) + 2)
	if err := binary.Write(buf, binary.LittleEndian, rawNameLen); err != nil {
		return err
	}

	labelCnt := uint8(len(labels))
	if err := binary.Write(buf, binary.LittleEndian, labelCnt); err != nil {
		return err
	}

	for _, label := range labels {
		labLen := uint8(len(label))
		if err := binary.Write(buf, binary.LittleEndian, labLen); err != nil {
			return err
		}
		if _, err := buf.WriteString(label); err != nil {
			return err
		}
	}

	if err := buf.WriteByte(0); err != nil {
		return err
	}

	return nil
}

func ParseCountNameSingle(data []byte) (string, error) {
	buf := bytes.NewReader(data)
	return ParseCountName(buf)
}

func (p *DNSProperty) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, p.DataLength); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, p.NameLength); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, p.Flag); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, p.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, p.Id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, p.Data); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, p.Name); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *DNSProperty) Decode(data []byte) error {
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &p.DataLength); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &p.NameLength); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &p.Flag); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &p.Version); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &p.Id); err != nil {
		return err
	}
	p.Data = make([]byte, p.DataLength)
	if err := binary.Read(buf, binary.LittleEndian, &p.Data); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &p.Name); err != nil {
		return err
	}
	return nil
}

// ADIDNS Record Types
// {Reference} MS-DNSP 2.2.2.2.4 DNS_RPC_RECORD_DATA
// IP addresses (v4 or v6) are stored using their string representations

// Interface to hold the parsed record fields
type RecordData interface {
	// Parses a record from its byte array in the Data field of the
	// DNSRecord AD attribute
	Parse([]byte)

	// Encode the record into a byte array to be used in the Data field
	// of the DNSRecord AD attribute
	Encode() []byte
}

// Using a bit of reflection so that
// I don't have to manually implement a DumpField
// method on every type
type Field struct {
	Name  any
	Value any
}

func DumpRecordFields(fr RecordData) []Field {
	result := make([]Field, 0)

	v := reflect.ValueOf(fr).Elem()
	for i := 0; i < v.NumField(); i++ {
		result = append(result, Field{v.Type().Field(i).Name, v.Field(i).Interface()})
	}

	return result
}

// 2.2.2.2.4.2 DNS_RPC_RECORD_NODE_NAME
type RecordNodeName struct {
	NameNode string
}

func (rnn *RecordNodeName) Parse(data []byte) {
	parsedName, err := ParseCountNameSingle(data)
	if err == nil {
		rnn.NameNode = parsedName
	}
}

func (rnn *RecordNodeName) Encode() []byte {
	buf := new(bytes.Buffer)

	EncodeCountName(buf, rnn.NameNode)

	return buf.Bytes()
}

// 2.2.2.2.4.6 DNS_RPC_RECORD_STRING
type RecordString struct {
	StrData []string
}

func (rs *RecordString) Parse(data []byte) {
	result := make([]string, 0)

	buf := bytes.NewReader(data)
	for buf.Len() > 0 {
		parsedName, err := ParseRpcName(buf)
		if err == nil {
			result = append(result, parsedName)
		}
	}

	rs.StrData = result
}

func (rs *RecordString) Encode() []byte {
	data := make([]byte, 0)

	for _, val := range rs.StrData {
		data = append(data, byte(len(val)))
		data = append(data, []byte(val)...)
	}

	return data
}

// 2.2.2.2.4.7 DNS_RPC_RECORD_MAIL_ERROR
type RecordMailError struct {
	MailBX      string
	ErrorMailBX string
}

func (rs *RecordMailError) Parse(data []byte) {
	buf := bytes.NewReader(data)

	mailBX, err := ParseCountName(buf)
	if err == nil {
		rs.MailBX = mailBX
	}

	errorMailBX, err := ParseCountName(buf)
	if err == nil {
		rs.ErrorMailBX = errorMailBX
	}
}

func (rs *RecordMailError) Encode() []byte {
	buf := new(bytes.Buffer)

	EncodeCountName(buf, rs.MailBX)

	EncodeCountName(buf, rs.ErrorMailBX)

	return buf.Bytes()
}

// 2.2.2.2.4.8 DNS_RPC_RECORD_NAME_PREFERENCE
type RecordNamePreference struct {
	Preference uint16
	Exchange   string
}

func (rnp *RecordNamePreference) Parse(data []byte) {
	rnp.Preference = binary.BigEndian.Uint16(data[:2])
	parsedName, err := ParseCountNameSingle(data[2:])
	if err == nil {
		rnp.Exchange = parsedName
	}
}

func (rnp *RecordNamePreference) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, rnp.Preference)

	EncodeCountName(buf, rnp.Exchange)

	return buf.Bytes()
}

type NSRecord = RecordNodeName
type MDRecord = RecordNodeName
type MFRecord = RecordNodeName
type CNAMERecord = RecordNodeName
type MBRecord = RecordNodeName
type MGRecord = RecordNodeName
type MRRecord = RecordNodeName
type PTRRecord = RecordNodeName
type DNAMERecord = RecordNodeName

type HINFORecord = RecordString
type ISDNRecord = RecordString
type TXTRecord = RecordString
type X25Record = RecordString
type LOCRecord = RecordString

type MINFORecord = RecordMailError
type RPRecord = RecordMailError

type MXRecord = RecordNamePreference
type AFSDBRecord = RecordNamePreference
type RTRecord = RecordNamePreference

// 2.2.2.2.4.23 DNS_RPC_RECORD_TS
type ZERORecord struct{}

func (zr *ZERORecord) Parse(data []byte) {}
func (zr *ZERORecord) Encode() []byte {
	return []byte{}
}

// 2.2.2.2.4.1 DNS_RPC_RECORD_A
type ARecord struct {
	Address string // Parsed from a [4]byte
}

func (v4r *ARecord) Parse(data []byte) {
	v4r.Address = ParseIP(data)
}

func (v4r *ARecord) Encode() []byte {
	ip := net.ParseIP(v4r.Address)
	return []byte(net.IP.To4(ip))
}

// 2.2.2.2.4.16 DNS_RPC_RECORD_AAAA
type AAAARecord struct {
	Address string // Parsed from a [16]byte
}

func (v6r *AAAARecord) Parse(data []byte) {
	v6r.Address = ParseIP(data)
}

func (v6r *AAAARecord) Encode() []byte {
	ip := net.ParseIP(v6r.Address)
	return []byte(net.IP.To16(ip))
}

// 2.2.2.2.4.3 DNS_RPC_RECORD_SOA
type SOARecord struct {
	Serial            uint32
	Refresh           uint32
	Retry             uint32
	Expire            uint32
	MinimumTTL        uint32
	NamePrimaryServer string
	ZoneAdminEmail    string
}

func (r *SOARecord) Parse(data []byte) {
	r.Serial = binary.BigEndian.Uint32(data[:4])
	r.Refresh = binary.BigEndian.Uint32(data[4:8])
	r.Retry = binary.BigEndian.Uint32(data[8:12])
	r.Expire = binary.BigEndian.Uint32(data[12:16])
	r.MinimumTTL = binary.BigEndian.Uint32(data[16:20])

	buf := bytes.NewReader(data[20:])
	parsedName, err := ParseCountName(buf)
	if err == nil {
		r.NamePrimaryServer = parsedName
	}

	parsedName, err = ParseCountName(buf)
	if err == nil {
		r.ZoneAdminEmail = parsedName
	}
}

func (r *SOARecord) Encode() []byte {
	buf := new(bytes.Buffer)

	fields := []uint32{r.Serial, r.Refresh, r.Retry, r.Expire, r.MinimumTTL}
	for _, field := range fields {
		binary.Write(buf, binary.BigEndian, field)
	}

	names := []string{r.NamePrimaryServer, r.ZoneAdminEmail}
	for _, name := range names {
		EncodeCountName(buf, name)
	}

	return buf.Bytes()
}

// 2.2.2.2.4.4 DNS_RPC_RECORD_NULL
type NULLRecord struct {
	Data []byte
}

func (r *NULLRecord) Parse(data []byte) {
	r.Data = data
}

func (r *NULLRecord) Encode() []byte {
	return r.Data
}

// 2.2.2.2.4.5 DNS_RPC_RECORD_WKS
type WKSRecord struct {
	Address  string
	Protocol uint8
	BitMask  []byte
}

func (r *WKSRecord) Parse(data []byte) {
	r.Address = ParseIP(data[:4])
	r.Protocol = data[4]
	r.BitMask = data[5:]
}

func (r *WKSRecord) Encode() []byte {
	ip := net.ParseIP(r.Address)

	data := []byte(net.IP.To4(ip))
	data = append(data, byte(r.Protocol))
	data = append(data, r.BitMask...)

	return data
}

// 2.2.2.2.4.9 DNS_RPC_RECORD_SIG
type SIGRecord struct {
	TypeCovered   uint16
	Algorithm     uint8
	Labels        uint8
	OriginalTTL   uint32
	SigExpiration uint32
	SigInception  uint32
	KeyTag        uint16
	NameSigner    string
	SignatureInfo []byte
}

func (r *SIGRecord) Parse(data []byte) {
	r.TypeCovered = binary.BigEndian.Uint16(data[:2])
	r.Algorithm = data[2]
	r.Labels = data[3]
	r.OriginalTTL = binary.BigEndian.Uint32(data[4:8])
	r.SigExpiration = binary.BigEndian.Uint32(data[8:12])
	r.SigInception = binary.BigEndian.Uint32(data[12:16])
	r.KeyTag = binary.BigEndian.Uint16(data[16:18])

	buf := bytes.NewReader(data[18:])
	parsedName, err := ParseCountName(buf)
	if err == nil {
		r.NameSigner = parsedName
	}

	sigInfo, _ := ioutil.ReadAll(buf)
	r.SignatureInfo = sigInfo
}

func (r *SIGRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.TypeCovered)

	buf.WriteByte(r.Algorithm)
	buf.WriteByte(r.Labels)

	binary.Write(buf, binary.BigEndian, r.OriginalTTL)
	binary.Write(buf, binary.BigEndian, r.SigExpiration)
	binary.Write(buf, binary.BigEndian, r.SigInception)
	binary.Write(buf, binary.BigEndian, r.KeyTag)

	EncodeCountName(buf, r.NameSigner)

	buf.Write(r.SignatureInfo)

	return buf.Bytes()
}

// 2.2.2.2.4.13 DNS_RPC_RECORD_KEY
type KEYRecord struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	Key       []byte
}

func (r *KEYRecord) Parse(data []byte) {
	r.Flags = binary.BigEndian.Uint16(data[:2])
	r.Protocol = data[2]
	r.Algorithm = data[3]
	r.Key = data[4:]
}

func (r *KEYRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, r.Flags); err != nil {
		return []byte{}
	}

	if err := buf.WriteByte(r.Protocol); err != nil {
		return []byte{}
	}

	if err := buf.WriteByte(r.Algorithm); err != nil {
		return []byte{}
	}

	if _, err := buf.Write(r.Key); err != nil {
		return []byte{}
	}

	return buf.Bytes()
}

// 2.2.2.2.4.17 DNS_RPC_RECORD_NXT
type NXTRecord struct {
	NumRecordTypes uint16
	TypeWords      []uint16
	NextName       string
}

func (r *NXTRecord) Parse(data []byte) {
	// TODO: Fix NXT parsing
	// This type does not seem to be following MS spec properly.
	// I'll just ignore it for the moment and hope to figure it out later.

	/*
		r.NumRecordTypes = binary.LittleEndian.Uint16(data[:2])
		r.TypeWords = make([]uint16, r.NumRecordTypes)

		offset := 2
		for i := uint16(0); i < r.NumRecordTypes; i++ {
			r.TypeWords[i] = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
		}

		parsedName, err := ParseRpcNameSingle(data[offset:])
		if err == nil {
			r.NextName = parsedName
		}
	*/
}

func (r *NXTRecord) Encode() []byte {
	// TODO: Fix NXT parsing
	return []byte{}
}

// 2.2.2.2.4.18 DNS_RPC_RECORD_SRV
type SRVRecord struct {
	Priority   uint16
	Weight     uint16
	Port       uint16
	NameTarget string
}

func (r *SRVRecord) Parse(data []byte) {
	r.Priority = binary.BigEndian.Uint16(data[:2])
	r.Weight = binary.BigEndian.Uint16(data[2:4])
	r.Port = binary.BigEndian.Uint16(data[4:6])

	parsedName, err := ParseCountNameSingle(data[6:])
	if err == nil {
		r.NameTarget = parsedName
	}
}

func (r *SRVRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.Priority)

	binary.Write(buf, binary.BigEndian, r.Weight)

	binary.Write(buf, binary.BigEndian, r.Port)

	EncodeCountName(buf, r.NameTarget)

	return buf.Bytes()
}

// 2.2.2.2.4.19 DNS_RPC_RECORD_ATMA
type ATMARecord struct {
	Format  uint8
	Address string
}

func (r *ATMARecord) Parse(data []byte) {
	r.Format = data[0]

	r.Address = string(data[1:])
}

func (r *ATMARecord) Encode() []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(r.Format)

	buf.WriteString(r.Address)

	return buf.Bytes()
}

// 2.2.2.2.4.20 DNS_RPC_RECORD_NAPTR
type NAPTRRecord struct {
	Order        uint16
	Preference   uint16
	Flags        string
	Service      string
	Substitution string
	Replacement  string
}

func (r *NAPTRRecord) Parse(data []byte) {
	var err error

	r.Order = binary.BigEndian.Uint16(data[:2])
	r.Preference = binary.BigEndian.Uint16(data[2:4])

	buf := bytes.NewReader(data[4:])

	flags, err := ParseRpcName(buf)
	if err == nil {
		r.Flags = flags
	}

	service, err := ParseRpcName(buf)
	if err == nil {
		r.Service = service
	}

	subst, err := ParseRpcName(buf)
	if err == nil {
		r.Substitution = subst
	}

	replacement, err := ParseCountName(buf)
	if err == nil {
		r.Replacement = replacement
	}
}

func (r *NAPTRRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.Order)

	binary.Write(buf, binary.BigEndian, r.Preference)

	EncodeRpcName(buf, r.Flags)

	EncodeRpcName(buf, r.Service)

	EncodeRpcName(buf, r.Substitution)

	EncodeCountName(buf, r.Replacement)

	return buf.Bytes()
}

// 2.2.2.2.4.12 DNS_RPC_RECORD_DS
type DSRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

func (r *DSRecord) Parse(data []byte) {
	r.KeyTag = binary.BigEndian.Uint16(data[:2])
	r.Algorithm = data[2]
	r.DigestType = data[3]
	r.Digest = data[4:]
}

func (r *DSRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.KeyTag)

	buf.WriteByte(r.Algorithm)

	buf.WriteByte(r.DigestType)

	buf.Write(r.Digest)

	return buf.Bytes()
}

// 2.2.2.2.4.10 DNS_RPC_RECORD_RRSIG
type RRSIGRecord = SIGRecord

// 2.2.2.2.4.11 DNS_RPC_RECORD_NSEC
type NSECRecord struct {
	NameSigner string
	NSECBitmap []byte
}

func (r *NSECRecord) Parse(data []byte) {
	buf := bytes.NewReader(data)
	parsedName, err := ParseCountName(buf)
	if err == nil {
		r.NameSigner = parsedName
	}

	r.NSECBitmap, _ = ioutil.ReadAll(buf)
}

func (r *NSECRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	EncodeCountName(buf, r.NameSigner)

	binary.Write(buf, binary.LittleEndian, r.NSECBitmap)

	return buf.Bytes()
}

// 2.2.2.2.4.15 DNS_RPC_RECORD_DNSKEY
type DNSKEYRecord struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	Key       []byte
}

func (r *DNSKEYRecord) Parse(data []byte) {
	r.Flags = binary.BigEndian.Uint16(data[:2])
	r.Protocol = data[2]
	r.Algorithm = data[3]
	r.Key = data[4:]
}

func (r *DNSKEYRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.Flags)

	buf.WriteByte(r.Protocol)

	buf.WriteByte(r.Algorithm)

	buf.Write(r.Key)

	return buf.Bytes()
}

// 2.2.2.2.4.14 DNS_RPC_RECORD_DHCID
type DHCIDRecord struct {
	Digest []byte
}

func (r *DHCIDRecord) Parse(data []byte) {
	r.Digest = data
}

func (r *DHCIDRecord) Encode() []byte {
	return r.Digest
}

// 2.2.2.2.4.24 DNS_RPC_RECORD_NSEC3
type NSEC3Record struct {
	Algorithm           uint8
	Flags               uint8
	Iterations          uint16
	SaltLength          uint8
	HashLength          uint8
	Salt                []byte
	NextHashedOwnerName []byte
	Bitmaps             []byte
}

func (r *NSEC3Record) Parse(data []byte) {
	r.Algorithm = data[0]
	r.Flags = data[1]
	r.Iterations = binary.BigEndian.Uint16(data[2:4])
	r.SaltLength = data[4]
	r.HashLength = data[5]
	r.Salt = data[6 : 6+int(r.SaltLength)]
	r.NextHashedOwnerName = data[6+int(r.SaltLength) : 6+int(r.SaltLength)+int(r.HashLength)]
	r.Bitmaps = data[6+int(r.SaltLength)+int(r.HashLength):]
}

func (r *NSEC3Record) Encode() []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(r.Algorithm)

	buf.WriteByte(r.Flags)

	binary.Write(buf, binary.BigEndian, r.Iterations)

	buf.WriteByte(r.SaltLength)

	buf.WriteByte(r.HashLength)

	buf.Write(r.Salt)

	buf.Write(r.NextHashedOwnerName)

	buf.Write(r.Bitmaps)

	return buf.Bytes()
}

// 2.2.2.2.4.25 DNS_RPC_RECORD_NSEC3PARAM
type NSEC3PARAMRecord struct {
	Algorithm  uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       []byte
}

func (r *NSEC3PARAMRecord) Parse(data []byte) {
	r.Algorithm = data[0]
	r.Flags = data[1]
	r.Iterations = binary.BigEndian.Uint16(data[2:4])
	r.SaltLength = data[4]
	r.Salt = data[5 : 5+int(r.SaltLength)]
}

func (r *NSEC3PARAMRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(r.Algorithm)

	buf.WriteByte(r.Flags)

	binary.Write(buf, binary.BigEndian, r.Iterations)

	buf.WriteByte(r.SaltLength)

	buf.Write(r.Salt)

	return buf.Bytes()
}

// 2.2.2.2.4.26 DNS_RPC_RECORD_TLSA
type TLSARecord struct {
	CertificateUsage           uint8
	Selector                   uint8
	MatchingType               uint8
	CertificateAssociationData []byte
}

func (r *TLSARecord) Parse(data []byte) {
	r.CertificateUsage = data[0]
	r.Selector = data[1]
	r.MatchingType = data[2]
	r.CertificateAssociationData = data[3:]
}

func (r *TLSARecord) Encode() []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(r.CertificateUsage)

	buf.WriteByte(r.Selector)

	buf.WriteByte(r.MatchingType)

	buf.Write(r.CertificateAssociationData)

	return buf.Bytes()
}

// 2.2.2.2.4.21 DNS_RPC_RECORD_WINS
type WINSRecord struct {
	MappingFlag   uint32
	LookupTimeout uint32
	CacheTimeout  uint32
	WinsSrvCount  uint32
	WinsServers   []uint32
}

func (r *WINSRecord) Parse(data []byte) {
	r.MappingFlag = binary.BigEndian.Uint32(data[:4])
	r.LookupTimeout = binary.BigEndian.Uint32(data[4:8])
	r.CacheTimeout = binary.BigEndian.Uint32(data[8:12])
	r.WinsSrvCount = binary.BigEndian.Uint32(data[12:16])

	for i := uint32(0); i < r.WinsSrvCount; i++ {
		addr := binary.BigEndian.Uint32(data[16+i*4 : 20+i*4])
		r.WinsServers = append(r.WinsServers, addr)
	}
}

func (r *WINSRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.MappingFlag)

	binary.Write(buf, binary.BigEndian, r.LookupTimeout)

	binary.Write(buf, binary.BigEndian, r.CacheTimeout)

	binary.Write(buf, binary.BigEndian, r.WinsSrvCount)

	for i := uint32(0); i < r.WinsSrvCount; i++ {
		binary.Write(buf, binary.BigEndian, r.WinsServers[i])
	}

	return buf.Bytes()
}

// 2.2.2.2.4.22 DNS_RPC_RECORD_WINSR
type WINSRRecord struct {
	MappingFlag      uint32
	LookupTimeout    uint32
	CacheTimeout     uint32
	NameResultDomain string
}

func (r *WINSRRecord) Parse(data []byte) {
	r.MappingFlag = binary.BigEndian.Uint32(data[:4])
	r.LookupTimeout = binary.BigEndian.Uint32(data[4:8])
	r.CacheTimeout = binary.BigEndian.Uint32(data[8:12])

	parsedName, err := ParseCountNameSingle(data[12:])
	if err == nil {
		r.NameResultDomain = parsedName
	}
}

func (r *WINSRRecord) Encode() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, r.MappingFlag)

	binary.Write(buf, binary.BigEndian, r.LookupTimeout)

	binary.Write(buf, binary.BigEndian, r.CacheTimeout)

	EncodeCountName(buf, r.NameResultDomain)

	return buf.Bytes()
}

func parseUint(value string) uint64 {
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed
}

func RecordFromInput(recordType string, recordValue any) RecordData {
	var fRecord RecordData

	switch recordType {
	case "ZERO":
		fRecord = new(ZERORecord)
	case "A":
		fRecord = new(ARecord)
		fRecord.(*ARecord).Address = recordValue.(string)
	case "AAAA":
		fRecord = new(AAAARecord)
		fRecord.(*AAAARecord).Address = recordValue.(string)
	case "CNAME":
		fRecord = new(CNAMERecord)
		fRecord.(*CNAMERecord).NameNode = recordValue.(string)
	case "TXT":
		fRecord = new(TXTRecord)
		fRecord.(*TXTRecord).StrData = recordValue.([]string)
	case "NS":
		fRecord = new(NSRecord)
		fRecord.(*NSRecord).NameNode = recordValue.(string)
	case "PTR":
		fRecord = new(PTRRecord)
		fRecord.(*PTRRecord).NameNode = recordValue.(string)
	case "MD":
		fRecord = new(MDRecord)
		fRecord.(*MDRecord).NameNode = recordValue.(string)
	case "MF":
		fRecord = new(MFRecord)
		fRecord.(*MFRecord).NameNode = recordValue.(string)
	case "MB":
		fRecord = new(MBRecord)
		fRecord.(*MBRecord).NameNode = recordValue.(string)
	case "MG":
		fRecord = new(MGRecord)
		fRecord.(*MGRecord).NameNode = recordValue.(string)
	case "MR":
		fRecord = new(MRRecord)
		fRecord.(*MRRecord).NameNode = recordValue.(string)
	case "DNAME":
		fRecord = new(DNAMERecord)
		fRecord.(*DNAMERecord).NameNode = recordValue.(string)
	case "HINFO":
		fRecord = new(HINFORecord)
		fRecord.(*HINFORecord).StrData = recordValue.([]string)
	case "ISDN":
		fRecord = new(ISDNRecord)
		fRecord.(*ISDNRecord).StrData = recordValue.([]string)
	case "X25":
		fRecord = new(X25Record)
		fRecord.(*X25Record).StrData = recordValue.([]string)
	case "LOC":
		fRecord = new(LOCRecord)
		fRecord.(*LOCRecord).StrData = recordValue.([]string)
	case "MX":
		valMap := recordValue.(map[string]string)
		fRecord = new(MXRecord)
		fRecord.(*MXRecord).Preference = uint16(parseUint(valMap["Preference"]))
		fRecord.(*MXRecord).Exchange = valMap["Exchange"]
	case "AFSDB":
		valMap := recordValue.(map[string]string)
		fRecord = new(AFSDBRecord)
		fRecord.(*AFSDBRecord).Preference = uint16(parseUint(valMap["Preference"]))
		fRecord.(*AFSDBRecord).Exchange = valMap["Exchange"]
	case "RT":
		valMap := recordValue.(map[string]string)
		fRecord = new(RTRecord)
		fRecord.(*RTRecord).Preference = uint16(parseUint(valMap["Preference"]))
		fRecord.(*RTRecord).Exchange = valMap["Exchange"]
	case "SRV":
		valMap := recordValue.(map[string]string)
		fRecord = new(SRVRecord)
		fRecord.(*SRVRecord).Priority = uint16(parseUint(valMap["Priority"]))
		fRecord.(*SRVRecord).Weight = uint16(parseUint(valMap["Weight"]))
		fRecord.(*SRVRecord).Port = uint16(parseUint(valMap["Port"]))
		fRecord.(*SRVRecord).NameTarget = valMap["NameTarget"]
	case "SOA":
		valMap := recordValue.(map[string]string)
		fRecord = new(SOARecord)
		fRecord.(*SOARecord).Serial = uint32(parseUint(valMap["Serial"]))
		fRecord.(*SOARecord).Refresh = uint32(parseUint(valMap["Refresh"]))
		fRecord.(*SOARecord).Retry = uint32(parseUint(valMap["Retry"]))
		fRecord.(*SOARecord).Expire = uint32(parseUint(valMap["Expire"]))
		fRecord.(*SOARecord).MinimumTTL = uint32(parseUint(valMap["MinimumTTL"]))
		fRecord.(*SOARecord).NamePrimaryServer = valMap["NamePrimaryServer"]
		fRecord.(*SOARecord).ZoneAdminEmail = valMap["ZoneAdminEmail"]
	default:
		fRecord = new(ZERORecord)
	}

	return fRecord
}
