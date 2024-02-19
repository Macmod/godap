package utils

// Constants for userAccountControl flags
const (
	UAC_SCRIPT                         = 0x00000001
	UAC_ACCOUNTDISABLE                 = 0x00000002
	UAC_HOMEDIR_REQUIRED               = 0x00000008
	UAC_LOCKOUT                        = 0x00000010
	UAC_PASSWD_NOTREQD                 = 0x00000020
	UAC_PASSWD_CANT_CHANGE             = 0x00000040
	UAC_ENCRYPTED_TEXT_PWD_ALLOWED     = 0x00000080
	UAC_TEMP_DUPLICATE_ACCOUNT         = 0x00000100
	UAC_NORMAL_ACCOUNT                 = 0x00000200
	UAC_INTERDOMAIN_TRUST_ACCOUNT      = 0x00000800
	UAC_WORKSTATION_TRUST_ACCOUNT      = 0x00001000
	UAC_SERVER_TRUST_ACCOUNT           = 0x00002000
	UAC_DONT_EXPIRE_PASSWORD           = 0x00010000
	UAC_MNS_LOGON_ACCOUNT              = 0x00020000
	UAC_SMARTCARD_REQUIRED             = 0x00040000
	UAC_TRUSTED_FOR_DELEGATION         = 0x00080000
	UAC_NOT_DELEGATED                  = 0x00100000
	UAC_USE_DES_KEY_ONLY               = 0x00200000
	UAC_DONT_REQ_PREAUTH               = 0x00400000
	UAC_PASSWORD_EXPIRED               = 0x00800000
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000
	UAC_PARTIAL_SECRETS_ACCOUNT        = 0x04000000
)

// Constants for Security Descriptor's Control Flags
const (
	SE_DACL_AUTO_INHERIT_REQ = 0x00000100
	SE_DACL_AUTO_INHERITED   = 0x00000400
	SE_DACL_SACL_DEFAULTED   = 0x00000008
	SE_DACL_PRESENT          = 0x00000004
	SE_DACL_PROTECTED        = 0x00001000
	SE_GROUP_DEFAULTED       = 0x00000002
	SE_OWNER_DEFAULTED       = 0x00000001
	SE_RM_CONTROL_VALID      = 0x00004000
	SE_SACL_AUTO_INHERIT_REQ = 0x00000200
	SE_SACL_AUTO_INHERITED   = 0x00000800
	SE_SACL_PRESENT          = 0x00000010
	SE_SACL_PROTECTED        = 0x00002000
	SE_SELF_RELATIVE         = 0x00008000
)

type flagDesc struct {
	Present    string
	NotPresent string
}

var UacFlags = map[int]flagDesc{
	UAC_SCRIPT:                         flagDesc{"Script", ""},
	UAC_ACCOUNTDISABLE:                 flagDesc{"Disabled", "Enabled"},
	UAC_HOMEDIR_REQUIRED:               flagDesc{"HomeDirRequired", ""},
	UAC_LOCKOUT:                        flagDesc{"LockedOut", ""},
	UAC_PASSWD_NOTREQD:                 flagDesc{"PwdNotRequired", ""},
	UAC_PASSWD_CANT_CHANGE:             flagDesc{"CannotChangePwd", ""},
	UAC_ENCRYPTED_TEXT_PWD_ALLOWED:     flagDesc{"EncryptedTextPwdAllowed", ""},
	UAC_TEMP_DUPLICATE_ACCOUNT:         flagDesc{"TmpDuplicateAccount", ""},
	UAC_NORMAL_ACCOUNT:                 flagDesc{"NormalAccount", ""},
	UAC_INTERDOMAIN_TRUST_ACCOUNT:      flagDesc{"InterdomainTrustAccount", ""},
	UAC_WORKSTATION_TRUST_ACCOUNT:      flagDesc{"WorkstationTrustAccount", ""},
	UAC_SERVER_TRUST_ACCOUNT:           flagDesc{"ServerTrustAccount", ""},
	UAC_DONT_EXPIRE_PASSWORD:           flagDesc{"DoNotExpirePwd", ""},
	UAC_MNS_LOGON_ACCOUNT:              flagDesc{"MNSLogonAccount", ""},
	UAC_SMARTCARD_REQUIRED:             flagDesc{"SmartcardRequired", ""},
	UAC_TRUSTED_FOR_DELEGATION:         flagDesc{"TrustedForDelegation", ""},
	UAC_NOT_DELEGATED:                  flagDesc{"NotDelegated", ""},
	UAC_USE_DES_KEY_ONLY:               flagDesc{"UseDESKeyOnly", ""},
	UAC_DONT_REQ_PREAUTH:               flagDesc{"DoNotRequirePreauth", ""},
	UAC_PASSWORD_EXPIRED:               flagDesc{"PwdExpired", "PwdNotExpired"},
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: flagDesc{"TrustedToAuthForDelegation", ""},
	UAC_PARTIAL_SECRETS_ACCOUNT:        flagDesc{"PartialSecretsAccount", ""},
}

var SDControlFlags = map[int]string{
	SE_DACL_AUTO_INHERIT_REQ: "SE_DACL_AUTO_INHERIT_REQ",
	SE_DACL_AUTO_INHERITED:   "SE_DACL_AUTO_INHERITED",
	SE_DACL_SACL_DEFAULTED:   "SE_DACL_SACL_DEFAULTED",
	SE_DACL_PRESENT:          "SE_DACL_PRESENT",
	SE_DACL_PROTECTED:        "SE_DACL_PROTECTED",
	SE_GROUP_DEFAULTED:       "SE_GROUP_DEFAULTED",
	SE_OWNER_DEFAULTED:       "SE_OWNER_DEFAULTED",
	SE_RM_CONTROL_VALID:      "SE_RM_CONTROL_VALID",
	SE_SACL_AUTO_INHERIT_REQ: "SE_SACL_AUTO_INHERIT_REQ",
	SE_SACL_AUTO_INHERITED:   "SE_SACL_AUTO_INHERITED",
	SE_SACL_PRESENT:          "SE_SACL_PRESENT",
	SE_SACL_PROTECTED:        "SE_SACL_PROTECTED",
	SE_SELF_RELATIVE:         "SE_SELF_RELATIVE",
}

// Relative ID (RID) descriptions
var RidMap = map[int]string{
	500: "Administrator",
	501: "Guest",
	502: "KRBTGT (Key Distribution Center Service Account)",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	526: "Key Admins",
	527: "Enterprise Key Admins",
	553: "RAS and IAS Servers",
	554: "Trusted for Delegation Computers",
	555: "Protected Users",
	572: "Cloneable Domain Controllers",
	573: "Read-only Domain Controllers",
	590: "Backup Operators",
	591: "Print Operators",
	592: "Server Operators",
	593: "Account Operators",
	594: "Replicator",
	596: "Incoming Forest Trust Builders",
	597: "Performance Monitor Users",
	598: "Performance Log Users",
	599: "Windows Authorization Access Group",
	600: "Network Configuration Operators",
	601: "Incoming Forest Trust Builders",
	606: "Cryptographic Operators",
	607: "Event Log Readers",
}

// sAMAccountType descriptions
var SAMAccountTypeMap = map[int]string{
	0x00000000: "Domain Object",
	0x10000000: "Group Object",
	0x10000001: "Non-Security Group Object",
	0x30000000: "User Object",
	0x30000001: "Machine Account",
	0x20000000: "Alias Object",
	0x20000001: "Non-Security Alias Object",
	0x30000002: "Trust Account",
	0x40000000: "App Basic Group",
	0x40000001: "App Query Group",
}

// groupType descriptions
var GroupTypeMap = map[int]string{
	2:           "Global Distribution Group",
	4:           "Domain Local Distribution Group",
	8:           "Universal Distribution Group",
	-2147483646: "Global Security Group",
	-2147483644: "Domain Local Security Group",
	-2147483643: "Builtin Group",
	-2147483640: "Universal Security Group",
}

// instanceType descriptions
var InstanceTypeMap = map[int]string{
	1:  "NamingContextHead",
	2:  "NotInstantiatedReplica",
	4:  "WritableObject",
	8:  "ParentNamingContextHeld",
	16: "FirstNamingContextConstruction",
	32: "NamingContextRemovalFromDSA",
}

var PredefinedLdapQueries = map[string]string{
	"DomainControllers":              "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
	"NonDCServers":                   "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
	"NonServerComputers":             "(&(objectCategory=computer)(!(operatingSystem=*server*))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
	"AllOrganizationalUnits":         "(objectCategory=organizationalUnit)",
	"AllContainers":                  "(objectCategory=container)",
	"AllGroups":                      "(objectCategory=group)",
	"AllComputers":                   "(objectClass=computer)",
	"AllUsers":                       "(&(objectCategory=person)(objectClass=user))",
	"UsersWithSPN":                   "(&(objectCategory=user)(servicePrincipalName=*))",
	"UsersWithSIDHistory":            "(&(objectCategory=person)(objectClass=user)(sidHistory=*))",
	"KrbPreauthDisabledUsers":        "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
	"KrbPreauthDisabledComputers":    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
	"CertificatePublishers":          "(CN=Cert Publishers*)",
	"ConstrainedDelegationObjects":   "(msDS-AllowedToDelegateTo=*)",
	"UnconstrainedDelegationObjects": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
	"RBCDObjects":                    "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
	"NotTrustedForDelegation":        "(&(samaccountname=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))",
	"ShadowCredentialsTargets":       "(msDS-KeyCredentialLink=*)",
	"UsersMustChangePassword":        "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))",
	"UsersWithNeverExpirePasswords":  "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
	"UsersWithEmptyPasswords":        "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))",
	"AdminAccounts":                  "(&(objectCategory=user)(memberOf=CN=Administrators,CN=Builtin,DC=domain,DC=com))",
	"LockedOutUserAccounts":          "(&(objectCategory=user)(lockoutTime>=1))",
	"HighPrivilegeUsers":             "(&(objectCategory=user)(adminCount=1))",
	"MembersOfDomainAdminsGroup":     "(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com))",
	"UsersWithPasswordNeverChanged":  "(&(objectCategory=user)(pwdLastSet=0))",
	"UsersWithEmptyDescription":      "(&(objectCategory=user)(description=*))",
	"UsersWithNoEmailAddress":        "(&(objectCategory=user)(!(mail=*)))",
	"UnusualAccountNames":            "(&(objectCategory=user)(sAMAccountName=*$*))",
	"ServiceAccountNames":            "(&(objectCategory=user)(sAMAccountName=*svc*))",
	"DisabledUserAccounts":           "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
	"StaleComputerAccounts":          "(&(objectCategory=computer)(!lastLogonTimestamp=*))",
	"UsersWithNonExpiringPasswords":  "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=66048))",
	"EnabledUsersNotInGroup":         "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(memberOf=*)))",
	"ComputersWithOutdatedOS":        "(&(objectCategory=computer)(operatingSystem=*Server 2008*))",
	"UsersWithSensitiveInformation":  "(&(objectCategory=user)(|(telephoneNumber=*)(pager=*)(homePhone=*)(mobile=*)(info=*)))",
	"RecentlyCreatedUsers":           "(&(objectCategory=user)(whenCreated>=<timestamp>))",
	"InactiveUsersLastLogonTime":     "(&(objectCategory=user)(lastLogonTimestamp<=<timestamp>))",
	"ExpiredUserAccounts":            "(&(objectCategory=user)(accountExpires<=<timestamp>))",
}

var WellKnownSIDsMap = map[string]string{
	"S-1-0-0":    "Null SID",
	"S-1-1-0":    "Everyone",
	"S-1-2-0":    "Local",
	"S-1-2-1":    "Console Logon",
	"S-1-3-0":    "Creator Owner ID",
	"S-1-3-1":    "Creator Group ID",
	"S-1-3-2":    "Creator Owner Server",
	"S-1-3-3":    "Creator Group Server",
	"S-1-3-4":    "Owner Rights",
	"S-1-4":      "Non-Unique Authority",
	"S-1-5":      "NT Authority",
	"S-1-5-80-0": "All Services",
	"S-1-5-1":    "Dialup",
	"S-1-5-113":  "Local Account",
	"S-1-5-114":  "Local account and member of Administrators group",
	"S-1-5-2":    "Network",
	"S-1-5-3":    "Batch",
	"S-1-5-4":    "Interactive",
	"S-1-5-6":    "Serivce",
	"S-1-5-7":    "Anonymous Logon",
	"S-1-5-8":    "Proxy",
	"S-1-5-9":    "Enterprise Domain Controllers",
	"S-1-5-10":   "Self",
	"S-1-5-11":   "Authenticated Users",
	"S-1-5-12":   "Restricted Code",
	"S-1-5-13":   "Terminal Server User",
	"S-1-5-14":   "Remote Interactive Logon",
	"S-1-5-15":   "This Organization",
	"S-1-5-17":   "IUSR",
	"S-1-5-18":   "SYSTEM",
	"S-1-5-19":   "NT Authority (LocalService)",
	"S-1-5-20":   "Network Service",
}
