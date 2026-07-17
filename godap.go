package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Macmod/godap/v2/pkg/debug"
	"github.com/Macmod/godap/v2/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var acceptableAuthFlagSets = []map[string]bool{
	{"username": true},
	{"username": true, "password": true},
	{"username": true, "passfile": true},
	{"username": true, "hash": true},
	{"username": true, "hashfile": true},
	{"kerberos": true},
	{"crt": true, "key": true},
	{"pfx": true},
}

func validateFlagSet(cmd *cobra.Command) error {
	used := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		used[f.Name] = true
	})

	matches := 0
	partials := 0

	for _, candidateSet := range acceptableAuthFlagSets {
		if containsAll(used, candidateSet) {
			if matches > 0 {
				return fmt.Errorf("Invalid authentication flags: mixed flags from multiple acceptable sets\nPlease use only one of {-u,-p},{-u,--passfile},{-u,-H},{-u,--hashfile},{-k},{--crt,--key},{--pfx}\nor none of these for anonymous binds.")
			}
			matches++
		} else if intersects(used, candidateSet) {
			partials++
		}
	}

	if matches == 0 && partials > 0 {
		return fmt.Errorf("Invalid authentication flags: missing required flags\nPlease use only one of {-u,-p},{-u,--passfile},{-u,-H},{-u,--hashfile},{-k},{--crt,--key},{--pfx}\nor none of these for anonymous binds.")
	}

	return nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, "--"+k)
	}
	return out
}

func containsAll(provided, required map[string]bool) bool {
	for k := range required {
		if !provided[k] {
			return false
		}
	}
	return true
}

func intersects(setA, setB map[string]bool) bool {
	for k := range setA {
		if setB[k] {
			return true
		}
	}
	return false
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "godap <server address>",
		Short: "A complete TUI for LDAP.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Apply GODAP_PASSWD env var when no explicit password flag was provided.
			if !cmd.Flags().Changed("password") && !cmd.Flags().Changed("passfile") {
				if envPw := os.Getenv("GODAP_PASSWD"); envPw != "" {
					tui.LdapPassword = envPw
				}
			}

			// Apply GODAP_SSH_PASSWORD env var when no explicit SSH password flag was provided.
			if !cmd.Flags().Changed("ssh-password") && !cmd.Flags().Changed("ssh-passfile") {
				if envPw := os.Getenv("GODAP_SSH_PASSWORD"); envPw != "" {
					tui.SSHTunnelPassword = envPw
				}
			}

			// --ssh-passfile: read password from file or prompt on "-".
			if cmd.Flags().Changed("ssh-passfile") {
				pw, err := tui.ReadFileOrStdin(tui.SSHTunnelPasswordFile, "SSH Password: ")
				if err != nil {
					log.Fatalf("Failed to read SSH password file: %v", err)
				}
				tui.SSHTunnelPassword = strings.TrimSpace(pw)
			}

			// Infer SSH auth method from flags; explicit --ssh-auth is honoured only as a fallback.
			sshAgentSet := tui.SSHTunnelAgentAuth
			sshKeySet := cmd.Flags().Changed("ssh-key")
			sshPassSet := tui.SSHTunnelPassword != ""
			switch {
			case sshAgentSet && sshKeySet:
				log.Fatal("Conflicting SSH auth flags: --ssh-agent and --ssh-key cannot both be set")
			case sshAgentSet && sshPassSet:
				log.Fatal("Conflicting SSH auth flags: --ssh-agent and --ssh-password/--ssh-passfile cannot both be set")
			case sshKeySet && sshPassSet:
				log.Fatal("Conflicting SSH auth flags: --ssh-key and --ssh-password/--ssh-passfile cannot both be set")
			case sshAgentSet:
				tui.SSHTunnelAuthMethod = "agent"
			case sshKeySet:
				tui.SSHTunnelAuthMethod = "key"
			case sshPassSet:
				tui.SSHTunnelAuthMethod = "password"
			}

			err := validateFlagSet(cmd)
			if err != nil {
				log.Fatalf(fmt.Sprint(err))
			}

			// Prompt for LDAP password when username is set but no password method was provided.
			if tui.LdapUsername != "" &&
				tui.LdapPassword == "" &&
				tui.LdapPasswordFile == "" &&
				tui.NtlmHash == "" &&
				tui.NtlmHashFile == "" &&
				!tui.Kerberos &&
				tui.CertFile == "" &&
				tui.PfxFile == "" {
				fmt.Print("LDAP Password: ")
				passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					log.Fatalf("Failed to read password: %v", err)
				}
				tui.LdapPassword = string(passwordBytes)
			}

			tui.LdapServer = args[0]

			if tui.LdapPort == 0 {
				if tui.Ldaps {
					tui.LdapPort = 636
				} else {
					tui.LdapPort = 389
				}
			}

			// A non-empty --ssh-host implicitly enables the tunnel.
			if tui.SSHTunnelHost != "" {
				tui.SSHTunnelEnabled = true
			}

			// Initialize debug log if requested.
			if tui.DebugLogPath != "" {
				if err := debug.Init(tui.DebugLogPath); err != nil {
					log.Printf("Warning: could not open debug log %q: %v", tui.DebugLogPath, err)
				} else {
					defer debug.Close()
				}
			}

			tui.SetupApp()
		},
	}

	rootCmd.Flags().IntVarP(&tui.LdapPort, "port", "P", 0, "LDAP server port")
	rootCmd.Flags().StringVarP(&tui.LdapUsername, "username", "u", "", "LDAP username")
	rootCmd.Flags().StringVarP(&tui.LdapPassword, "password", "p", "", "LDAP password")
	rootCmd.Flags().StringVarP(&tui.LdapPasswordFile, "passfile", "", "", "Path to a file containing the LDAP password (or - for stdin)")
	rootCmd.Flags().StringVarP(&tui.DomainName, "domain", "d", "", "Domain for NTLM / Kerberos authentication")
	rootCmd.Flags().StringVarP(&tui.NtlmHash, "hash", "H", "", "NTLM hash")
	rootCmd.Flags().BoolVarP(&tui.Kerberos, "kerberos", "k", false, "Use Kerberos ticket for authentication (CCACHE specified via KRB5CCNAME environment variable)")
	rootCmd.Flags().StringVarP(&tui.TargetSpn, "spn", "t", "", "Target SPN to use for Kerberos bind (usually ldap/dchostname)")
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
	rootCmd.Flags().StringVarP(&tui.SocksServer, "socks", "x", "", "Use a SOCKS proxy for initial connection")
	rootCmd.Flags().StringVarP(&tui.KdcHost, "kdc", "", "", "Address of the KDC to use with Kerberos authentication (optional: only if the KDC differs from the specified LDAP server)")
	rootCmd.Flags().StringVarP(&tui.TimeFormat, "timefmt", "", "", "Time format for LDAP timestamps")
	rootCmd.Flags().StringVarP(&tui.CertFile, "crt", "", "", "Path to a file containing the certificate to use for the bind")
	rootCmd.Flags().StringVarP(&tui.KeyFile, "key", "", "", "Path to a file containing the private key to use for the bind")
	rootCmd.Flags().StringVarP(&tui.PfxFile, "pfx", "", "", "Path to a file containing the PFX to use for the bind")
	rootCmd.Flags().StringVarP(&tui.AttrSort, "attrsort", "", "none", "Sort attributes by name (none, asc, desc)")
	rootCmd.Flags().IntVarP(&tui.TimeOffset, "offset", "", 0, "Offset in hours to apply to formatted timestamps")
	rootCmd.Flags().StringVarP(&tui.ExportDir, "exportdir", "", "data", "Custom directory to save godap exports taken with Ctrl+S")
	rootCmd.Flags().StringVarP(&tui.BackendFlavor, "backend", "b", "msad", "LDAP backend flavor (msad, basic or auto)")

	// SSH tunnel flags
	rootCmd.Flags().StringVar(&tui.SSHTunnelHost, "ssh-host", "", "SSH tunnel host (also enables the tunnel when non-empty)")
	rootCmd.Flags().IntVar(&tui.SSHTunnelPort, "ssh-port", 22, "SSH tunnel port")
	rootCmd.Flags().StringVar(&tui.SSHTunnelUser, "ssh-user", os.Getenv("USER"), "SSH tunnel username")
	rootCmd.Flags().StringVar(&tui.SSHTunnelAuthMethod, "ssh-auth", "password", "SSH auth method: password, key, or agent (deprecated: inferred automatically from other flags)")
	rootCmd.Flags().StringVar(&tui.SSHTunnelPassword, "ssh-password", "", "SSH tunnel password")
	rootCmd.Flags().StringVar(&tui.SSHTunnelPasswordFile, "ssh-passfile", "", "Path to a file containing the SSH tunnel password (or - for stdin)")
	rootCmd.Flags().BoolVar(&tui.SSHTunnelAgentAuth, "ssh-agent", false, "Use SSH agent for tunnel authentication")
	rootCmd.Flags().StringVar(&tui.SSHTunnelKeyFile, "ssh-key", "", "Path to SSH private key file")
	rootCmd.Flags().StringVar(&tui.SSHTunnelKeyPassphrase, "ssh-key-passphrase", "", "Passphrase for SSH private key")
	rootCmd.Flags().BoolVar(&tui.SSHTunnelInsecure, "ssh-ignore-host-key", false, "Skip SSH host key verification (insecure)")
	rootCmd.Flags().StringVar(&tui.DebugLogPath, "debug-log", "", "Path to debug log file")

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
