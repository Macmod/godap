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
	"UsersWithSPN":                    "(&(objectCategory=user)(servicePrincipalName=*))",
	"DisabledUserAccounts":            "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
	"StaleComputerAccounts":           "(&(objectCategory=computer)(!lastLogonTimestamp=*))",
	"UsersWithEmptyPasswords":         "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))",
	"AdminAccounts":                   "(&(objectCategory=user)(memberOf=CN=Administrators,CN=Builtin,DC=domain,DC=com))",
	"UsersWithNeverExpirePasswords":   "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
	"LockedOutUserAccounts":           "(&(objectCategory=user)(lockoutTime>=1))",
	"HighPrivilegeUsers":              "(&(objectCategory=user)(adminCount=1))",
	"MembersOfDomainAdminsGroup":      "(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com))",
	"UsersWithPasswordNeverChanged":   "(&(objectCategory=user)(pwdLastSet=0))",
	"ComputersWithNullSessionEnabled": "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
	"UsersWithEmptyDescription":       "(&(objectCategory=user)(description=*))",
	"UsersWithNoEmailAddress":         "(&(objectCategory=user)(!(mail=*)))",
	"UnusualAccountNames":             "(&(objectCategory=user)(sAMAccountName=*$*))",
	"ServiceAccountNames":             "(&(objectCategory=user)(sAMAccountName=*svc*))",
	"UsersWithNonExpiringPasswords":   "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=66048))",
	"EnabledUsersNotInGroup":          "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(memberOf=*)))",
	"ComputersWithOutdatedOS":         "(&(objectCategory=computer)(operatingSystem=*Server 2008*))",
	"UsersWithSensitiveInformation":   "(&(objectCategory=user)(|(telephoneNumber=*)(pager=*)(homePhone=*)(mobile=*)(info=*)))",
	"RecentlyCreatedUsers":            "(&(objectCategory=user)(whenCreated>=<timestamp>))",
	"InactiveUsersLastLogonTime":      "(&(objectCategory=user)(lastLogonTimestamp<=<timestamp>))",
	"ExpiredUserAccounts":             "(&(objectCategory=user)(accountExpires<=<timestamp>))",
}
