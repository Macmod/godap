package main

import (
	"fmt"

	"github.com/Macmod/godap/v2/tui"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "godap <server address>",
		Short: "A complete TUI for LDAP.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tui.LdapServer = args[0]

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
	rootCmd.Flags().StringVarP(&tui.LdapPasswordFile, "passfile", "", "", "Path to a file containing the LDAP password")
	rootCmd.Flags().StringVarP(&tui.DomainName, "domain", "d", "", "Domain for NTLM / Kerberos authentication")
	rootCmd.Flags().StringVarP(&tui.NtlmHash, "hash", "H", "", "NTLM hash")
	rootCmd.Flags().BoolVarP(&tui.Kerberos, "kerberos", "k", false, "Use Kerberos ticket for authentication (CCACHE specified via KRB5CCNAME environment variable)")
	rootCmd.Flags().StringVarP(&tui.TargetSpn, "spn", "t", "", "Target SPN to use for Kerberos bind (usually ldap/dchostname)")
	rootCmd.Flags().StringVarP(&tui.NtlmHashFile, "hashfile", "", "", "Path to a file containing the NTLM hash")
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
	rootCmd.Flags().StringVarP(&tui.SocksServer, "socks", "x", "", "Use a SOCKS proxy for initial connection")
	rootCmd.Flags().StringVarP(&tui.KdcHost, "kdc", "", "", "Address of the KDC to use with Kerberos authentication (optional: only if the KDC differs from the specified LDAP server)")
	rootCmd.Flags().StringVarP(&tui.TimeFormat, "timefmt", "", "", "Time format for LDAP timestamps")
	rootCmd.Flags().StringVarP(&tui.CertFile, "crt", "", "", "Path to a file containing the certificate to use for the bind")
	rootCmd.Flags().StringVarP(&tui.KeyFile, "key", "", "", "Path to a file containing the private key to use for the bind")
	rootCmd.Flags().StringVarP(&tui.PfxFile, "pfx", "", "", "Path to a file containing the PFX to use for the bind")
	rootCmd.Flags().StringVarP(&tui.AttrSort, "attrsort", "", "none", "Sort attributes by name (none, asc, desc)")
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
