package tui

import (
	"context"
	"crypto/x509"
	"strings"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/rivo/tview"
)

// fieldKey identifies one of the shared credential/connection input widgets
// that an authMechanism's page may include. The string value doubles as the
// form label, so it's the single source of truth for both.
type fieldKey string

const (
	fUsername     fieldKey = "Username"
	fPassword     fieldKey = "Password"
	fPassFile     fieldKey = "Password File"
	fNTLMHash     fieldKey = "NTLM Hash"
	fNTLMHashFile fieldKey = "NTLM Hash File"
	fAESKey       fieldKey = "AES Key"
	fCCache       fieldKey = "CCACHE Path"
	fKDC          fieldKey = "KDC Address"
	fCertFile     fieldKey = "Certificate Path"
	fKeyFile      fieldKey = "Key Path"
	fPfxFile      fieldKey = "PFX Path"
)

// fieldSpec ties a fieldKey to the global variable it edits and how the
// widget should be rendered.
type fieldSpec struct {
	Password bool
	Get      func() string
	Set      func(string)
}

var fieldCatalog = map[fieldKey]fieldSpec{
	fUsername:     {Get: func() string { return LdapUsername }, Set: func(v string) { LdapUsername = v }},
	fPassword:     {Password: true, Get: func() string { return LdapPassword }, Set: func(v string) { LdapPassword = v }},
	fPassFile:     {Get: func() string { return LdapPasswordFile }, Set: func(v string) { LdapPasswordFile = v }},
	fNTLMHash:     {Password: true, Get: func() string { return NtlmHash }, Set: func(v string) { NtlmHash = v }},
	fNTLMHashFile: {Get: func() string { return NtlmHashFile }, Set: func(v string) { NtlmHashFile = v }},
	fAESKey:       {Password: true, Get: func() string { return AESKey }, Set: func(v string) { AESKey = v }},
	fCCache:       {Get: func() string { return CCachePath }, Set: func(v string) { CCachePath = v }},
	fKDC:          {Get: func() string { return KdcHost }, Set: func(v string) { KdcHost = v }},
	fCertFile:     {Get: func() string { return CertFile }, Set: func(v string) { CertFile = v }},
	fKeyFile:      {Get: func() string { return KeyFile }, Set: func(v string) { KeyFile = v }},
	fPfxFile:      {Get: func() string { return PfxFile }, Set: func(v string) { PfxFile = v }},
}

// buildFieldsPage creates an XForm exposing exactly the given fields,
// pre-filled from the current globals.
func buildFieldsPage(fields []fieldKey) *XForm {
	page := NewXForm()
	for _, key := range fields {
		spec := fieldCatalog[key]
		if spec.Password {
			page.AddPasswordField(string(key), spec.Get(), 20, '*', nil)
		} else {
			page.AddInputField(string(key), spec.Get(), 20, nil, nil)
		}
	}
	return page
}

// applyFieldsPage writes each field's current widget value on the page back
// into its backing global.
func applyFieldsPage(page *XForm, fields []fieldKey) {
	for _, key := range fields {
		item := page.GetFormItemByLabel(string(key)).(*tview.InputField)
		fieldCatalog[key].Set(item.GetText())
	}
}

// resolveSecret returns the value read from fileFlag (or a terminal prompt
// if fileFlag is "-"), falling back to inline if fileFlag is empty. This is
// the pattern every *File credential variant already needs (previously
// repeated inline per auth code); centralizing it here is what lets a single
// mechanism page offer both the inline and file-backed form of a credential
// without needing a separate dropdown entry for each.
func resolveSecret(inline, fileFlag, promptIfTerm string) (string, error) {
	if fileFlag == "" {
		return strings.TrimSpace(inline), nil
	}
	v, err := readFileOrStdin(fileFlag, promptIfTerm)
	return strings.TrimSpace(v), err
}

// splitDomainAndUsername extracts a domain embedded in a UPN (user@domain)
// or NetBIOS-style (DOMAIN\user) username, mirroring the same two formats
// adauth's own (unexported) splitter recognizes. Returns domain == "" when u
// carries no domain, in which case username == u unchanged.
func splitDomainAndUsername(u string) (domain, username string) {
	if at := strings.Index(u, "@"); at >= 0 {
		return u[at+1:], u[:at]
	}
	if bs := strings.Index(u, `\`); bs >= 0 {
		return u[:bs], u[bs+1:]
	}
	return "", u
}

func loadCert() (*x509.Certificate, any, error) {
	if PfxFile != "" {
		return ldaputils.LoadClientCertPFX(PfxFile)
	}
	return ldaputils.LoadClientCertPEM(CertFile, KeyFile)
}

// authMechanism describes one selectable bind mechanism in the config form:
// its display label, which shared fields it exposes, and how to actually
// perform the bind from the current global credential values.
//
// This is the single source of truth for what auth methods godap exposes at
// runtime. The config form's dropdown, its per-mechanism pages, and the bind
// dispatch in setupLDAPConn are all driven from authMechanisms below instead
// of duplicating a numeric code across independent switch statements - every
// mechanism that exists is automatically selectable, and every field a
// mechanism's Bind closure consults is automatically shown on its page.
type authMechanism struct {
	ID     string
	Label  string
	Fields []fieldKey
	// Bind performs the actual LDAP bind for this mechanism using whichever
	// of Fields are currently non-empty, returning the resulting connection,
	// a human-readable bind type for the status log, whether the connection
	// is already secured by a client certificate (independent of LDAPS), and
	// any error.
	Bind func(ctx context.Context, params ldaputils.ConnectParams) (conn *ldaputils.LDAPConn, bindType string, secure bool, err error)
}

var authMechanisms = []authMechanism{
	{
		ID:     "simple",
		Label:  "Simple Bind",
		Fields: []fieldKey{fUsername, fPassword, fPassFile},
		Bind: func(ctx context.Context, params ldaputils.ConnectParams) (*ldaputils.LDAPConn, string, bool, error) {
			pw, err := resolveSecret(LdapPassword, LdapPasswordFile, "Password: ")
			if err != nil {
				return nil, "", false, err
			}
			lc, err := ldaputils.LDAPBind(ctx, params, ldapIdentity(), pw)
			return lc, "Simple", false, err
		},
	},
	{
		ID:     "ntlm",
		Label:  "NTLM",
		Fields: []fieldKey{fUsername, fNTLMHash, fNTLMHashFile, fPassword, fPassFile},
		Bind: func(ctx context.Context, params ldaputils.ConnectParams) (*ldaputils.LDAPConn, string, bool, error) {
			if NtlmHash != "" || NtlmHashFile != "" {
				hash, err := resolveSecret(NtlmHash, NtlmHashFile, "NTLM hash: ")
				if err != nil {
					return nil, "", false, err
				}
				lc, err := ldaputils.NTLMBindWithHash(ctx, params, DomainName, LdapUsername, hash)
				return lc, "NTLM", false, err
			}
			pw, err := resolveSecret(LdapPassword, LdapPasswordFile, "Password: ")
			if err != nil {
				return nil, "", false, err
			}
			lc, err := ldaputils.NTLMBindWithPassword(ctx, params, DomainName, LdapUsername, pw)
			return lc, "NTLM", false, err
		},
	},
	{
		ID:    "kerberos",
		Label: "Kerberos",
		Fields: []fieldKey{
			fUsername, fCCache, fKDC,
			fPassword, fPassFile, fNTLMHash, fNTLMHashFile, fAESKey,
			fCertFile, fKeyFile, fPfxFile,
		},
		// Precedence mirrors godap.go's documented CLI precedence
		// (aes-key > hash/hashfile > password/passfile > ccache), with a
		// client certificate (PKINIT) taking priority over all of them since
		// it's a categorically different, stronger credential.
		Bind: func(ctx context.Context, params ldaputils.ConnectParams) (*ldaputils.LDAPConn, string, bool, error) {
			switch {
			case PfxFile != "" || (CertFile != "" && KeyFile != ""):
				cert, key, err := loadCert()
				if err != nil {
					return nil, "", false, err
				}
				lc, err := ldaputils.KerbBindWithPKINIT(ctx, params, DomainName, LdapUsername, cert, key)
				return lc, "Kerberos+PKINIT", true, err
			case AESKey != "":
				lc, err := ldaputils.KerbBindWithAESKey(ctx, params, DomainName, LdapUsername, strings.TrimSpace(AESKey))
				return lc, "Kerberos", false, err
			case NtlmHash != "" || NtlmHashFile != "":
				hash, err := resolveSecret(NtlmHash, NtlmHashFile, "NTLM hash: ")
				if err != nil {
					return nil, "", false, err
				}
				lc, err := ldaputils.KerbBindWithNTHash(ctx, params, DomainName, LdapUsername, hash)
				return lc, "Kerberos", false, err
			case LdapPassword != "" || LdapPasswordFile != "":
				pw, err := resolveSecret(LdapPassword, LdapPasswordFile, "Password: ")
				if err != nil {
					return nil, "", false, err
				}
				lc, err := ldaputils.KerbBindWithPassword(ctx, params, DomainName, LdapUsername, pw)
				return lc, "Kerberos", false, err
			default:
				lc, err := ldaputils.KerbBindWithCCache(ctx, params, CCachePath, DomainName, LdapUsername)
				return lc, "Kerberos", false, err
			}
		},
	},
	{
		ID:     "certificate",
		Label:  "Certificate",
		Fields: []fieldKey{fCertFile, fKeyFile, fPfxFile},
		Bind: func(ctx context.Context, params ldaputils.ConnectParams) (*ldaputils.LDAPConn, string, bool, error) {
			cert, key, err := loadCert()
			if err != nil {
				return nil, "", false, err
			}
			lc, err := ldaputils.ExternalBind(ctx, params, cert, key)
			return lc, "LDAP+ClientCertificate", true, err
		},
	},
}

func indexOfMechanism(id string) int {
	for i, m := range authMechanisms {
		if m.ID == id {
			return i
		}
	}
	return 0
}

func mechanismByID(id string) authMechanism {
	return authMechanisms[indexOfMechanism(id)]
}

// resolveMechanismID picks the auth mechanism implied by the current CLI
// flags at startup, mirroring the outer branching godap.go's
// validateFlagSet already documents (a client cert, --kerberos and
// --simple are mutually exclusive at this outer level). Which
// credential wins *within* a mechanism (e.g. AES key vs. NT hash vs.
// password under Kerberos) is no longer resolved here - it's decided by
// that mechanism's own Bind closure above from whichever fields are
// non-empty, so this function only needs to pick the outer mechanism.
func resolveMechanismID() string {
	hasCert := PfxFile != "" || (CertFile != "" && KeyFile != "")

	switch {
	case hasCert && !Kerberos:
		return "certificate"
	case Kerberos:
		return "kerberos"
	case SimpleBind:
		return "simple"
	case NtlmHash != "" || NtlmHashFile != "":
		return "ntlm"
	case LdapPassword != "" || LdapPasswordFile != "":
		return "ntlm" // new default for -p/--passfile without --simple
	default:
		return "simple" // anonymous bind, unchanged default with zero auth flags
	}
}
