package utils

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/gssapi"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"

	"golang.org/x/text/encoding/unicode"
)

// Basic LDAP connection type
type LDAPConn struct {
	Conn       *ldap.Conn
	PagingSize uint32
	RootDN     string
}

func (lc *LDAPConn) UpgradeToTLS(tlsConfig *tls.Config) error {
	if lc.Conn == nil {
		return fmt.Errorf("Current connection is invalid")
	}

	err := lc.Conn.StartTLS(tlsConfig)
	if err != nil {
		return err
	}

	return nil
}

func NewLDAPConn(ldapServer string, ldapPort int, ldaps bool, tlsConfig *tls.Config, pagingSize uint32, rootDN string, proxyConn net.Conn) (*LDAPConn, error) {
	var conn *ldap.Conn
	var err error = nil

	if proxyConn == nil {
		if ldaps {
			conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort), tlsConfig)
		} else {
			conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
		}
	} else {
		if ldaps {
			conn = ldap.NewConn(tls.Client(proxyConn, tlsConfig), true)
		} else {
			conn = ldap.NewConn(proxyConn, false)
		}
		conn.Start()
	}

	if err != nil {
		return nil, err
	}

	return &LDAPConn{
		Conn:       conn,
		PagingSize: pagingSize,
		RootDN:     rootDN,
	}, nil
}

func (lc *LDAPConn) LDAPBind(ldapUsername string, ldapPassword string) error {
	err := lc.Conn.Bind(ldapUsername, ldapPassword)
	return err
}

func (lc *LDAPConn) NTLMBindWithHash(ntlmDomain string, ntlmUsername string, ntlmHash string) error {
	err := lc.Conn.NTLMBindWithHash(ntlmDomain, ntlmUsername, ntlmHash)
	return err
}

func (lc *LDAPConn) KerbBindWithCCache(ccachePath string, server string, krbDomain string, spnTarget string, etype string) error {
	var err error
	var etypeid int32

	switch etype {
	case "rc4":
		etypeid = 23
	case "aes":
		etypeid = 18
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return err
	}

	krbConf := config.New()
	krbConf.LibDefaults.DefaultRealm = krbDomain
	krbConf.LibDefaults.PermittedEnctypeIDs = []int32{etypeid}
	krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeid}
	krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeid}
	krbConf.LibDefaults.UDPPreferenceLimit = 1

	var realm config.Realm
	realm.Realm = strings.ToUpper(krbDomain)
	realm.KDC = []string{fmt.Sprintf("%s:88", server)}
	realm.DefaultDomain = strings.ToUpper(krbDomain)

	krbConf.Realms = []config.Realm{realm}

	rawKrbClient, err := client.NewFromCCache(ccache, krbConf)
	if err != nil {
		return err
	}

	wrappedClient := &gssapi.Client{
		Client: rawKrbClient,
	}

	err = wrappedClient.Login()
	if err != nil {
		return err
	}

	_, err = lc.Conn.SPNEGOBind(wrappedClient.Client, spnTarget)
	return err
}

// Search
func (lc *LDAPConn) Query(baseDN string, searchFilter string, scope int, showDeleted bool) ([]*ldap.Entry, error) {
	var controls []ldap.Control = nil
	if showDeleted {
		controls = []ldap.Control{ldap.NewControlMicrosoftShowDeleted()}
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{},
		controls,
	)

	sr, err := lc.Conn.SearchWithPaging(searchRequest, lc.PagingSize)
	if err != nil {
		return nil, err
	}

	return sr.Entries, nil
}

func (lc *LDAPConn) FindNamingContexts() ([]string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	)

	searchResult, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) < 1 {
		return nil, fmt.Errorf("No entries found")
	}

	return searchResult.Entries[0].GetAttributeValues("namingContexts"), nil
}

func (lc *LDAPConn) FindRootDN() (string, error) {
	var rootDN string
	avoidablePrefixes := []string{
		"CN=Schema", "CN=Configuration",
		"DC=DomainDnsZones", "DC=ForestDnsZones",
	}

	rDNCandidates, err := lc.FindNamingContexts()
	if err != nil {
		return "", err
	}

	for _, rootDNCandidate := range rDNCandidates {
		include := true
		for _, prefix := range avoidablePrefixes {
			if strings.HasPrefix(rootDNCandidate, prefix) {
				include = false
			}
		}

		if include {
			rootDN = rootDNCandidate
			break
		}
	}

	return rootDN, nil
}

func (lc *LDAPConn) FindRootFQDN() (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"ldapServiceName"},
		nil,
	)

	searchResult, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) == 0 {
		return "", fmt.Errorf("ldapServiceName attribute not found")
	}

	ldapSN := searchResult.Entries[0].GetAttributeValue("ldapServiceName")
	ldapSNTokens := strings.Split(ldapSN, "@")
	dnsRoot := ldapSNTokens[1]

	return dnsRoot, nil
}

func (lc *LDAPConn) QueryGroupMembers(groupDN string) (group []*ldap.Entry, err error) {
	ldapQuery := fmt.Sprintf("(memberOf=%s)", ldap.EscapeFilter(groupDN))

	search := ldap.NewSearchRequest(
		lc.RootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapQuery,
		[]string{"sAMAccountName", "objectCategory"},
		nil,
	)

	result, err := lc.Conn.Search(search)
	if err != nil {
		return nil, err
	}

	return result.Entries, nil
}

func (lc *LDAPConn) AddMemberToGroup(memberDN string, groupDN string) error {
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Add("member", []string{memberDN})
	err := lc.Conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (lc *LDAPConn) QueryUserGroups(userName string) ([]*ldap.Entry, error) {
	samOrDn, _ := SamOrDN(userName)

	search := ldap.NewSearchRequest(
		lc.RootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		samOrDn,
		[]string{"memberOf"},
		nil,
	)

	result, err := lc.Conn.Search(search)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("User '%s' not found", userName)
	}

	return result.Entries, nil
}

func (lc *LDAPConn) FindFirstDN(identifier string) (string, error) {
	samOrDn, _ := SamOrDN(identifier)

	entries, err := lc.Query(lc.RootDN, samOrDn, ldap.ScopeWholeSubtree, false)
	if err != nil {
		return "", err
	}

	if len(entries) > 0 {
		return entries[0].DN, nil
	} else {
		return "", fmt.Errorf("Object not found")
	}
}

// User Passwords
// Reference: https://gist.github.com/Project0/61c13130563cf7f595e031d54fe55aab
const (
	ldapAttrAccountName                        = "sAMAccountName"
	ldapAttrDN                                 = "dn"
	ldapAttrUAC                                = "userAccountControl"
	ldapAttrUPN                                = "userPrincipalName" // username@logon.domain
	ldapAttrEmail                              = "mail"
	ldapAttrUnicodePw                          = "unicodePwd"
	controlTypeLdapServerPolicyHints           = "1.2.840.113556.1.4.2239"
	controlTypeLdapServerPolicyHintsDeprecated = "1.2.840.113556.1.4.2066"
)

type (
	// ldapControlServerPolicyHints implements ldap.Control
	ldapControlServerPolicyHints struct {
		oid string
	}
)

func (c *ldapControlServerPolicyHints) GetControlType() string {
	return c.oid
}

func (c *ldapControlServerPolicyHints) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Control Type (LDAP_SERVER_POLICY_HINTS_OID)"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Policy Hints)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PolicyHintsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Flags"))
	p2.AppendChild(seq)
	packet.AppendChild(p2)

	return packet
}

func (c *ldapControlServerPolicyHints) String() string {
	return "Enforce password history policies during password set: " + c.GetControlType()
}

func (lc *LDAPConn) ResetPassword(objectDN string, newPassword string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", newPassword))
	if err != nil {
		return err
	}

	controlTypes, err := getSupportedControl(lc.Conn)
	if err != nil {
		return err
	}
	control := []ldap.Control{}
	for _, oid := range controlTypes {
		if oid == controlTypeLdapServerPolicyHints || oid == controlTypeLdapServerPolicyHintsDeprecated {
			control = append(control, &ldapControlServerPolicyHints{oid: oid})
			break
		}
	}

	passReq := ldap.NewModifyRequest(objectDN, control)
	passReq.Replace(ldapAttrUnicodePw, []string{pwdEncoded})
	return lc.Conn.Modify(passReq)
}

func getSupportedControl(conn ldap.Client) ([]string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	return res.Entries[0].GetAttributeValues("supportedControl"), nil
}

// Old version of LDAPResetPassword
/*
func LDAPChangePassword(conn *ldap.Conn, targetDN string, oldPassword string, newPassword string) error {
    var err error

	passwordModifyRequest := ldap.NewPasswordModifyRequest(targetDN, oldPassword, newPassword)

	_, err = conn.PasswordModify(passwordModifyRequest)
	if err != nil {
		return err
	}

	return nil
}
*/

// Objects
func (lc *LDAPConn) DeleteObject(targetDN string) error {
	var err error

	deleteRequest := ldap.NewDelRequest(targetDN, nil)

	err = lc.Conn.Del(deleteRequest)
	if err != nil {
		return err
	}

	return nil
}

func (lc *LDAPConn) AddGroup(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "group"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})

	return lc.Conn.Add(addRequest)
}

func (lc *LDAPConn) AddOrganizationalUnit(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("OU="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "organizationalUnit"})
	addRequest.Attribute("ou", []string{objectName})

	return lc.Conn.Add(addRequest)
}

func (lc *LDAPConn) AddContainer(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "container"})

	return lc.Conn.Add(addRequest)
}

func (lc *LDAPConn) AddComputer(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "computer"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName + "$"})
	addRequest.Attribute("userAccountControl", []string{"4096"})

	return lc.Conn.Add(addRequest)
}

func (lc *LDAPConn) AddUser(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})
	rootFQDN, err := lc.FindRootFQDN()

	if err == nil {
		userPrincipalName := fmt.Sprintf("%s@%s", objectName, strings.ToLower(rootFQDN))
		addRequest.Attribute(
			"userPrincipalName",
			[]string{userPrincipalName},
		)
	}

	return lc.Conn.Add(addRequest)
}

// Attributes
func (lc *LDAPConn) AddAttribute(targetDN string, attributeToAdd string, attributeValues []string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Add(attributeToAdd, attributeValues)

	err = lc.Conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (lc *LDAPConn) ModifyAttribute(targetDN string, attributeToModify string, attributeValues []string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Replace(attributeToModify, attributeValues)

	err = lc.Conn.Modify(modifyRequest)
	return err
}

func (lc *LDAPConn) DeleteAttribute(targetDN string, attributeToDelete string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Delete(attributeToDelete, []string{})

	err = lc.Conn.Modify(modifyRequest)
	return err
}

func (lc *LDAPConn) MoveObject(sourceDN string, targetDN string) error {
	var err error

	targetRDNs := strings.Split(targetDN, ",")

	targetFirstRDN := ""
	if len(targetRDNs) > 0 {
		targetFirstRDN = targetRDNs[0]
	}

	targetNewParent := ""
	if len(targetRDNs) > 1 {
		targetNewParent = strings.Join(targetRDNs[1:], ",")
	}

	modifyDNRequest := ldap.NewModifyDNRequest(sourceDN, targetFirstRDN, true, targetNewParent)

	err = lc.Conn.ModifyDN(modifyDNRequest)

	return err
}

type ControlMicrosoftSDFlags struct {
	Criticality  bool
	ControlValue int32
}

func (c *ControlMicrosoftSDFlags) GetControlType() string {
	return "1.2.840.113556.1.4.801"
}

func (c *ControlMicrosoftSDFlags) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "1.2.840.113556.1.4.801", "Control Type"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value(SDFlags)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlags")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.ControlValue, "Flags"))
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

func (c *ControlMicrosoftSDFlags) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %d", "1.2.840.113556.1.4.801",
		"1.2.840.113556.1.4.801", c.Criticality, c.ControlValue)
}

func (lc *LDAPConn) GetSecurityDescriptor(object string) (queryResult string, err error) {
	samOrDn, _ := SamOrDN(object)
	searchReq := ldap.NewSearchRequest(
		lc.RootDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		samOrDn,
		[]string{"nTSecurityDescriptor"},
		// ControlValue=15 in order to get SACLs too
		[]ldap.Control{&ControlMicrosoftSDFlags{ControlValue: 7}},
	)

	result, err := lc.Conn.Search(searchReq)
	if err != nil {
		return "", err
	}

	if len(result.Entries) > 0 {
		sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
		hexSD := hex.EncodeToString(sd)
		return hexSD, nil
	}

	return "", fmt.Errorf("Object '%s' not found", object)
}

func (lc *LDAPConn) FindFirstAttr(filter string, attr string) (string, error) {
	objectSearch := ldap.NewSearchRequest(
		lc.RootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{attr},
		nil,
	)

	result, err := lc.Conn.Search(objectSearch)
	if err != nil {
		return "", err
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("Search for '%s' returned 0 results", filter)
	}

	return result.Entries[0].GetAttributeValue(attr), nil
}

func SamOrDN(object string) (string, bool) {
	if strings.Contains(object, "=") {
		return fmt.Sprintf("(distinguishedName=%s)", ldap.EscapeFilter(object)), false
	}

	return fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(object)), true
}

func (lc *LDAPConn) ModifyDACL(objectName string, newSD string) error {
	samOrDn, isSam := SamOrDN(objectName)
	objectDN := objectName
	if isSam {
		dn, err := lc.FindFirstAttr(samOrDn, "distinguishedName")
		if err != nil {
			return err
		}
		objectDN = dn
	}

	modifyReq := ldap.NewModifyRequest(
		objectDN,
		[]ldap.Control{&ControlMicrosoftSDFlags{ControlValue: 7}},
	)

	modifyReq.Replace("nTSecurityDescriptor", []string{newSD})

	err := lc.Conn.Modify(modifyReq)
	return err
}

func (lc *LDAPConn) FindSIDForObject(object string) (SID string, err error) {
	found := false
	wellKnownSID := ""
	for key, val := range WellKnownSIDsMap {
		if strings.ToLower(val) == strings.ToLower(object) {
			found = true
			wellKnownSID = key
		}
	}

	if found {
		return wellKnownSID, nil
	}

	queryFilter, _ := SamOrDN(object)
	sidAttr, err := lc.FindFirstAttr(queryFilter, "objectSid")
	if err == nil {
		principalSID := ConvertSID(hex.EncodeToString([]byte(sidAttr)))
		return principalSID, nil
	}

	return "", err
}

func (lc *LDAPConn) FindSamForSID(SID string) (resolvedSID string, err error) {
	for entry, _ := range WellKnownSIDsMap {
		if SID == entry {
			return WellKnownSIDsMap[entry], nil
		}
	}

	query := fmt.Sprintf("(objectSID=%s)", SID)
	searchReq := ldap.NewSearchRequest(
		lc.RootDN,
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		query,
		[]string{},
		nil,
	)

	result, err := lc.Conn.Search(searchReq)
	if err != nil {
		return "", err
	}

	if len(result.Entries) > 0 {
		resolvedSID = result.Entries[0].GetAttributeValues("sAMAccountName")[0]
		return resolvedSID, nil
	}

	return "", fmt.Errorf("No entries found")
}

func (lc *LDAPConn) FindPrimaryGroupForSID(SID string) (groupSID string, err error) {
	domainSID, err := lc.FindSIDForObject(lc.RootDN)
	if err != nil {
		return "", err
	}

	query := fmt.Sprintf("(objectSID=%s)", SID)
	searchReq := ldap.NewSearchRequest(
		lc.RootDN,
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		query,
		[]string{"primaryGroupID"},
		nil,
	)

	result, err := lc.Conn.Search(searchReq)
	if err != nil {
		return "", err
	}

	if len(result.Entries) > 0 {
		resolvedRID := result.Entries[0].GetAttributeValue("primaryGroupID")
		if resolvedRID != "" {
			return domainSID + "-" + resolvedRID, nil
		}
	}

	return "", fmt.Errorf("No entries found")
}

func (lc *LDAPConn) FindSchemaControlAccessRights(filter string) (map[string]string, error) {
	extendedRights := make(map[string]string)

	rootDSE, err := lc.Query("", "(objectClass=*)", ldap.ScopeBaseObject, false)
	if err != nil {
		return nil, err
	}

	configurationDN := rootDSE[0].GetAttributeValue("configurationNamingContext")

	extendedEntries, err := lc.Query(
		"CN=Extended-Rights,"+configurationDN,
		filter,
		ldap.ScopeSingleLevel,
		false,
	)

	if err != nil {
		return nil, err
	}

	for _, entry := range extendedEntries {
		cn := entry.GetAttributeValue("cn")
		guidRights := entry.GetAttributeValue("rightsGuid")

		if len(guidRights) > 0 {
			extendedRights[strings.ToLower(guidRights)] = cn
		}
	}

	return extendedRights, nil
}

func (lc *LDAPConn) FindSchemaClassesAndAttributes() (map[string]string, map[string]string, error) {
	classesGuids := make(map[string]string)
	attrsGuids := make(map[string]string)

	rootDSE, err := lc.Query("", "(objectClass=*)", ldap.ScopeBaseObject, false)
	if err != nil {
		return nil, nil, err
	}

	schemaDN := rootDSE[0].GetAttributeValue("schemaNamingContext")

	schemaEntries, err := lc.Query(
		schemaDN,
		"(|(objectClass=attributeSchema)(objectClass=classSchema))",
		ldap.ScopeSingleLevel,
		false,
	)

	if err != nil {
		return nil, nil, err
	}

	for _, entry := range schemaEntries {
		cn := entry.GetAttributeValue("cn")
		cat := entry.GetAttributeValue("objectCategory")
		guid := entry.GetRawAttributeValue("schemaIDGUID")

		if len(guid) > 0 {
			guidConverted := ConvertGUID(hex.EncodeToString(guid))
			if strings.HasPrefix(cat, "CN=Class-Schema") {
				classesGuids[strings.ToLower(guidConverted)] = cn
			} else if strings.HasPrefix(cat, "CN=Attribute-Schema") {
				attrsGuids[strings.ToLower(guidConverted)] = cn
			}
		}
	}

	return classesGuids, attrsGuids, nil
}
