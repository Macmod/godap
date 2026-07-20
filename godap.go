package main

import (
	"fmt"
	"log"

	"github.com/Macmod/godap/v2/tui"
	"github.com/spf13/cobra"
)

// validateFlagSet checks the auth-related flags for known-nonsensical
// combinations. It intentionally does not try to enforce "exactly one
// acceptable set" via a flat list of disjoint flag-name sets (the
// pre-migration algorithm) - the new design has --kerberos legitimately
// combine with --password/--hash/--aes-key, which are supersets of each
// other in exactly the way that approach can't represent without producing
// false "mixed flags" errors. See resolveAuthMode below for the actual
// precedence resolution; this function only rejects combinations that can
// never resolve to anything sensible, regardless of precedence.
func validateFlagSet(cmd *cobra.Command) error {
	changed := func(name string) bool { return cmd.Flags().Changed(name) }

	hasCert := changed("crt") || changed("key") || changed("pfx")
	if changed("crt") != changed("key") {
		return fmt.Errorf("invalid authentication flags: --crt and --key must be given together")
	}
	if hasCert && changed("pfx") && (changed("crt") || changed("key")) {
		return fmt.Errorf("invalid authentication flags: --crt/--key and --pfx are mutually exclusive")
	}

	if changed("password") && changed("passfile") {
		return fmt.Errorf("invalid authentication flags: --password and --passfile are mutually exclusive")
	}
	if changed("hash") && changed("hashfile") {
		return fmt.Errorf("invalid authentication flags: --hash and --hashfile are mutually exclusive")
	}

	if changed("simple") {
		if changed("kerberos") || changed("hash") || changed("hashfile") || changed("aes-key") || hasCert {
			return fmt.Errorf("invalid authentication flags: --simple only makes sense with " +
				"-u/--username and -p/--password (or --passfile), not with --kerberos, --hash/--hashfile, " +
				"--aes-key, or a client certificate")
		}
	}

	credentialFlagsGiven := 0
	for _, name := range []string{"password", "passfile", "hash", "hashfile", "aes-key"} {
		if changed(name) {
			credentialFlagsGiven++
		}
	}
	if changed("kerberos") && credentialFlagsGiven > 1 {
		fmt.Fprintf(log.Writer(),
			"warning: multiple credential flags given with --kerberos; using precedence "+
				"aes-key > hash/hashfile > password/passfile > ccache (see resolveAuthMode)\n")
	}

	if (changed("password") || changed("passfile")) && !changed("username") {
		return fmt.Errorf("invalid authentication flags: -p/--password or --passfile requires -u/--username")
	}
	if (changed("hash") || changed("hashfile")) && !changed("username") {
		return fmt.Errorf("invalid authentication flags: -H/--hash or --hashfile requires -u/--username")
	}
	if changed("aes-key") && !changed("username") {
		return fmt.Errorf("invalid authentication flags: --aes-key requires -u/--username")
	}

	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "godap [server address]",
		Short: "A complete TUI for LDAP.",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := validateFlagSet(cmd); err != nil {
				log.Fatal(err)
			}

			if len(args) > 0 {
				tui.LdapServer = args[0]
			}

			if tui.LdapServer == "" && tui.DomainName == "" && !domainInUsername(tui.LdapUsername) {
				log.Fatalf("target host is required (or -d/--domain / a domain-qualified -u/--username, " +
					"to discover a domain controller automatically)")
			}

			if tui.LdapPort == 0 {
				if tui.Ldaps {
					tui.LdapPort = 636
				} else {
					tui.LdapPort = 389
				}
			}

			tui.SetupApp()
		},
	}

	rootCmd.Flags().IntVarP(&tui.LdapPort, "port", "P", 0, "LDAP server port")
	rootCmd.Flags().StringVarP(&tui.LdapUsername, "username", "u", "", "LDAP username")
	rootCmd.Flags().StringVarP(&tui.LdapPassword, "password", "p", "", "LDAP password")
	rootCmd.Flags().StringVarP(&tui.LdapPasswordFile, "passfile", "", "", "Path to a file containing the LDAP password (or - for stdin)")
	rootCmd.Flags().StringVarP(&tui.DomainName, "domain", "d", "", "Domain for NTLM / Kerberos authentication, or for DC discovery when the target is omitted")
	rootCmd.Flags().StringVarP(&tui.NtlmHash, "hash", "H", "", "NTLM hash")
	rootCmd.Flags().StringVarP(&tui.AESKey, "aes-key", "", "", "Kerberos AES128/AES256 key (hex-encoded); use with --kerberos")
	rootCmd.Flags().BoolVarP(&tui.SimpleBind, "simple", "", false, "Force a simple LDAP bind for -u/-p instead of the default NTLM")
	rootCmd.Flags().BoolVarP(&tui.Kerberos, "kerberos", "k", false, "Use Kerberos authentication - combine with -p/-H/--aes-key for AS-REQ, --crt/--key/--pfx for PKINIT, or alone for CCACHE (via KRB5CCNAME)")
	rootCmd.Flags().StringVarP(&tui.NtlmHashFile, "hashfile", "", "", "Path to a file containing the NTLM hash (or - for stdin)")
	rootCmd.Flags().StringVarP(&tui.RootDN, "rootDN", "r", "", "Initial root DN")
	rootCmd.Flags().StringVarP(&tui.SearchFilter, "filter", "f", "(objectClass=*)", "Initial LDAP search filter")
	rootCmd.Flags().BoolVarP(&tui.Emojis, "emojis", "E", true, "Prefix objects with emojis")
	rootCmd.Flags().BoolVarP(&tui.Colors, "colors", "C", true, "Colorize objects")
	rootCmd.Flags().BoolVarP(&tui.FormatAttrs, "format", "F", true, "Format attributes into human-readable values")
	rootCmd.Flags().BoolVarP(&tui.ExpandAttrs, "expand", "A", true, "Expand multi-value attributes")
	rootCmd.Flags().IntVarP(&tui.AttrLimit, "limit", "L", 20, "Number of attribute values to render for multi-value attributes when -expand is set true")
	rootCmd.Flags().BoolVarP(&tui.CacheEntries, "cache", "M", true, "Keep loaded entries in memory while the program is open and don't query them again")
	rootCmd.Flags().BoolVarP(&tui.Deleted, "deleted", "D", false, "Include deleted objects in all queries performed")
	rootCmd.Flags().Int32VarP(&tui.Timeout, "timeout", "T", 10, "Timeout for LDAP connections in seconds")
	rootCmd.Flags().BoolVarP(&tui.LoadSchema, "schema", "s", false, "Load schema GUIDs from the LDAP server during initialization")
	rootCmd.Flags().Uint32VarP(&tui.PagingSize, "paging", "G", 800, "Default paging size for regular queries")
	rootCmd.Flags().BoolVarP(&tui.Insecure, "insecure", "I", false, "Skip TLS verification for LDAPS/StartTLS")
	rootCmd.Flags().BoolVarP(&tui.Ldaps, "ldaps", "S", false, "Use LDAPS for initial connection")
	rootCmd.Flags().StringVarP(&tui.SocksServer, "socks", "x", "", "Use a SOCKS proxy for the LDAP connection and all Kerberos KDC traffic")
	rootCmd.Flags().StringVarP(&tui.KdcHost, "kdc", "", "", "Address of the KDC to use with Kerberos authentication (optional: only if the KDC differs from the specified LDAP server)")
	rootCmd.Flags().StringVarP(&tui.CustomDNS, "dns", "", "", "Custom DNS resolver IP[:port] for DC discovery and SPN/hostname lookups")
	rootCmd.Flags().BoolVarP(&tui.ForceDNSTCP, "dns-tcp", "", false, "Force DNS queries over TCP instead of UDP")
	rootCmd.Flags().BoolVarP(&tui.NoProxyDNS, "no-proxy-dns", "", false, "Do not route DNS queries through the SOCKS5 proxy (only relevant with -x/--socks)")
	rootCmd.Flags().StringVarP(&tui.TimeFormat, "timefmt", "", "", "Time format for LDAP timestamps")
	rootCmd.Flags().StringVarP(&tui.CertFile, "crt", "", "", "Path to a file containing the certificate to use for the bind")
	rootCmd.Flags().StringVarP(&tui.KeyFile, "key", "", "", "Path to a file containing the private key to use for the bind")
	rootCmd.Flags().StringVarP(&tui.PfxFile, "pfx", "", "", "Path to a file containing the PFX to use for the bind")
	rootCmd.Flags().StringVarP(&tui.AttrSort, "attrsort", "", "none", "Sort attributes by name (none, asc, desc)")
	rootCmd.Flags().IntVarP(&tui.TimeOffset, "offset", "", 0, "Offset in hours to apply to formatted timestamps")
	rootCmd.Flags().StringVarP(&tui.ExportDir, "exportdir", "", "data", "Custom directory to save godap exports taken with Ctrl+S")
	rootCmd.Flags().StringVarP(&tui.BackendFlavor, "backend", "b", "msad", "LDAP backend flavor (msad, basic or auto)")

	versionCmd := &cobra.Command{
		Use:                   "version",
		Short:                 "Print the version number of the application",
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(tui.GodapVer)
		},
	}

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

// domainInUsername reports whether u already carries a domain (user@domain or
// DOMAIN\user), which is enough to attempt DC discovery even without -d.
func domainInUsername(u string) bool {
	for _, r := range u {
		if r == '@' || r == '\\' {
			return true
		}
	}
	return false
}
