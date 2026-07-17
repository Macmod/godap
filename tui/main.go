package tui

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/godap/v2/pkg/debug"
	"github.com/Macmod/godap/v2/pkg/ldaputils"
	sshtunnel "github.com/Macmod/godap/v2/pkg/ssh"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/term"
	"h12.io/socks"
	"software.sslmate.com/src/go-pkcs12"
)

var GodapVer = "Godap v2.11.1"
var (
	LdapServer       string
	LdapPort         int
	TimeOffset       int
	LdapUsername     string
	LdapPassword     string
	LdapPasswordFile string
	NtlmHash         string
	NtlmHashFile     string
	DomainName       string
	SocksServer      string
	TargetSpn        string
	KdcHost          string
	TimeFormat       string
	CertFile         string
	KeyFile          string
	PfxFile          string
	CCachePath       string
	BackendFlavor    string

	Kerberos     bool
	Emojis       bool
	Colors       bool
	FormatAttrs  bool
	ExpandAttrs  bool
	AttrSort     string
	AttrLimit    int
	CacheEntries bool
	Deleted      bool
	LoadSchema   bool
	PagingSize   uint32
	Timeout      int32
	Insecure     bool
	Ldaps        bool
	SearchFilter string
	RootDN       string
	ShowHeader   bool
	AuthType     int
	ExportDir    string

	// SSH tunnel settings
	SSHTunnelEnabled       bool
	SSHTunnelHost          string
	SSHTunnelPort          int
	SSHTunnelUser          string
	SSHTunnelAuthMethod    string
	SSHTunnelPassword      string
	SSHTunnelKeyFile       string
	SSHTunnelKeyPassphrase string
	SSHTunnelInsecure      bool
	DebugLogPath           string

	page int
)

var (
	appPanel    *tview.Flex
	headerPanel *tview.Flex
	rootNode    *tview.TreeNode
	logPanel    *tview.TextView

	statusPanel        *tview.TextView
	tlsPanel           *tview.TextView
	formatFlagPanel    *tview.TextView
	emojiFlagPanel     *tview.TextView
	colorFlagPanel     *tview.TextView
	expandFlagPanel    *tview.TextView
	sortAttrsFlagPanel *tview.TextView
	deletedFlagPanel   *tview.TextView

	tlsConfig    *tls.Config
	lc           = &ldaputils.LDAPConn{}
	err          error
	activeTunnel *sshtunnel.Tunnel
)

type GodapPage struct {
	idx   int
	prim  tview.Primitive
	title string
}

var app = tview.NewApplication()

var pages = tview.NewPages()

var info = tview.NewTextView()

var insecureTlsConfig = &tls.Config{InsecureSkipVerify: true}

var secureTlsConfig = &tls.Config{InsecureSkipVerify: false}

func readPass(msgIfTerm string) string {
	fd := int(os.Stdin.Fd())

	var password string

	if terminal.IsTerminal(fd) {
		// Stdin is a terminal
		fmt.Print(msgIfTerm)
		passwordBytes, _ := term.ReadPassword(fd)
		password = string(passwordBytes)
		fmt.Println()
	} else {
		// Stdin is a pipe or file
		reader := bufio.NewReader(os.Stdin)
		password, _ = reader.ReadString('\n')
		password = strings.TrimSuffix(password, "\n")
	}

	return password
}

func toggleFlagF() {
	FormatAttrs = !FormatAttrs
	updateStateBox(formatFlagPanel, FormatAttrs)

	nodeExplorer := treePanel.GetCurrentNode()
	if nodeExplorer != nil {
		reloadExplorerAttrsPanel(nodeExplorer, CacheEntries)
	}
	nodeSearch := searchTreePanel.GetCurrentNode()
	if nodeSearch != nil {
		reloadSearchAttrsPanel(nodeSearch, CacheEntries)
	}
}

func toggleFlagE() {
	Emojis = !Emojis
	updateStateBox(emojiFlagPanel, Emojis)
	updateEmojis()
}

func toggleFlagC() {
	Colors = !Colors
	updateStateBox(colorFlagPanel, Colors)

	nodeExplorer := treePanel.GetCurrentNode()
	if nodeExplorer != nil {
		reloadExplorerAttrsPanel(nodeExplorer, CacheEntries)
	}

	nodeSearch := searchTreePanel.GetCurrentNode()
	if nodeSearch != nil {
		reloadSearchAttrsPanel(nodeSearch, CacheEntries)
	}
}

func reloadAllAttrPanels() {
	nodeExplorer := treePanel.GetCurrentNode()
	if nodeExplorer != nil {
		reloadExplorerAttrsPanel(nodeExplorer, CacheEntries)
	}
	selectAnchoredAttribute(explorerAttrsPanel)

	nodeSearch := searchTreePanel.GetCurrentNode()
	if nodeSearch != nil {
		reloadSearchAttrsPanel(nodeSearch, CacheEntries)
	}
	selectAnchoredAttribute(searchAttrsPanel)
}

func toggleFlagA() {
	ExpandAttrs = !ExpandAttrs
	updateStateBox(expandFlagPanel, ExpandAttrs)

	reloadAllAttrPanels()
}

func toggleFlagD() {
	Deleted = !Deleted
	updateStateBox(deletedFlagPanel, Deleted)
}

func updateSortStateBox(option string) {
	go app.QueueUpdateDraw(func() {
		switch option {
		case "none":
			sortAttrsFlagPanel.SetText("OFF")
			sortAttrsFlagPanel.SetTextColor(tcell.GetColor("red"))
		case "asc":
			sortAttrsFlagPanel.SetText("ASC")
			sortAttrsFlagPanel.SetTextColor(tcell.GetColor("green"))
		default:
			sortAttrsFlagPanel.SetText("DESC")
			sortAttrsFlagPanel.SetTextColor(tcell.GetColor("green"))
		}
	})
}

func toggleFlagS() {
	if AttrSort == "none" {
		AttrSort = "asc"
	} else if AttrSort == "asc" {
		AttrSort = "desc"
	} else {
		AttrSort = "none"
	}

	updateSortStateBox(AttrSort)

	reloadAllAttrPanels()
}

func toggleHeader() {
	ShowHeader = !ShowHeader
	if ShowHeader {
		appPanel.RemoveItem(headerPanel)
	} else {
		appPanel.RemoveItem(pages)
		appPanel.AddItem(headerPanel, 3, 0, false)
		appPanel.AddItem(pages, 0, 8, false)
	}
}

func writeDataExport(data map[string]any, dumpSuffix string, dumpFormat string) {
	unixTimestamp := time.Now().UnixMilli()
	outputFilename := fmt.Sprintf("%d_%s.json", unixTimestamp, dumpSuffix)

	objectToExport := map[string]any{
		"Data":   data,
		"Format": dumpFormat,
	}

	jsonExportMap, _ := json.MarshalIndent(objectToExport, "", " ")

	err := os.MkdirAll(ExportDir, 0755)
	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	}

	outputFilepath := filepath.Join(ExportDir, outputFilename)
	err = ioutil.WriteFile(outputFilepath, jsonExportMap, 0644)

	if err != nil {
		updateLog(fmt.Sprintf("%s", err), "red")
	} else {
		updateLog("File '"+outputFilepath+"' saved successfully!", "green")
	}
}

func upgradeStartTLS() {
	go func() {
		err = lc.UpgradeToTLS(tlsConfig)
		if err != nil {
			// handleLDAPError intentionally not called
			// as it's fairly common for the user to
			// just forget to enable -I to skip TLS verification
			updateLog(fmt.Sprint(err), "red")
		} else {
			updateLog("StartTLS request successful", "green")
			updateStateBox(tlsPanel, true)
		}

		updateStateBox(statusPanel, err == nil)
	}()
}

func reconnectLdap() {
	go app.QueueUpdateDraw(func() {
		connErr := setupLDAPConn()
		if connErr != nil {
			var hkErr *sshtunnel.HostKeyUnknownError
			if errors.As(connErr, &hkErr) {
				showHostKeyModal(hkErr.Host)
			}
		}
	})
}

func getCurrentAuthType() int {
	if PfxFile != "" {
		return 6 // Certificate (PKCS#12)
	}

	if CertFile != "" && KeyFile != "" {
		return 5 // Certificate (PEM)
	}

	if Kerberos {
		return 4 // Kerberos
	}

	if NtlmHashFile != "" {
		return 3 // NTLM (file)
	}

	if NtlmHash != "" {
		return 2 // NTLM
	}

	if LdapPasswordFile != "" {
		return 1 // Password (file)
	}

	return 0 // Password (default)
}

func openConfigForm() {
	currentFocus := app.GetFocus()

	// Main config form with connection settings
	configForm := NewXForm()
	configForm.
		AddInputField("Server", LdapServer, 20, nil, nil).
		AddInputField("Port", strconv.Itoa(LdapPort), 20, nil, nil).
		AddCheckbox("LDAPS", Ldaps, nil).
		AddCheckbox("IgnoreCert", Insecure, nil).
		AddInputField("SOCKSProxy", SocksServer, 20, nil, nil).
		AddInputField("Domain", DomainName, 20, nil, nil).
		AddDropDown("Auth Type", []string{
			"Password",
			"Password (file)",
			"NTLM",
			"NTLM (file)",
			"Kerberos",
			"Certificate (PEM)",
			"Certificate (PKCS#12)",
		}, 0, nil)

	// Credentials forms for each auth type
	passwordForm := NewXForm()
	passwordForm.
		AddInputField("Username", LdapUsername, 20, nil, nil).
		AddPasswordField("Password", LdapPassword, 20, '*', nil)

	passwordFileForm := NewXForm()
	passwordFileForm.
		AddInputField("Username", LdapUsername, 20, nil, nil).
		AddInputField("Password File", LdapPasswordFile, 20, nil, nil)

	ntlmForm := NewXForm()
	ntlmForm.
		AddInputField("Username", LdapUsername, 20, nil, nil).
		AddPasswordField("NTLM Hash", NtlmHash, 20, '*', nil)

	ntlmFileForm := NewXForm()
	ntlmFileForm.
		AddInputField("Username", LdapUsername, 20, nil, nil).
		AddInputField("Hash File", NtlmHashFile, 20, nil, nil)

	kerberosForm := NewXForm()
	kerberosForm.
		AddInputField("CCACHE Path", CCachePath, 20, nil, nil).
		AddInputField("Target SPN", TargetSpn, 20, nil, nil).
		AddInputField("KDC Address", KdcHost, 20, nil, nil)

	pfxForm := NewXForm()
	pfxForm.
		AddInputField("PFX Path", PfxFile, 20, nil, nil)

	pemForm := NewXForm()
	pemForm.
		AddInputField("Certificate Path", CertFile, 20, nil, nil).
		AddInputField("Key Path", KeyFile, 20, nil, nil)

	// Create pages to switch between auth forms
	authPages := tview.NewPages()
	authPages.
		AddPage("password", passwordForm, true, true).
		AddPage("passwordfile", passwordFileForm, true, false).
		AddPage("ntlm", ntlmForm, true, false).
		AddPage("ntlmfile", ntlmFileForm, true, false).
		AddPage("kerberos", kerberosForm, true, false).
		AddPage("pem", pemForm, true, false).
		AddPage("pfx", pfxForm, true, false)

	// Handle auth type selection
	configForm.GetFormItemByLabel("Auth Type").(*tview.DropDown).
		SetSelectedFunc(func(text string, index int) {
			switch index {
			case 0:
				authPages.SwitchToPage("password")
			case 1:
				authPages.SwitchToPage("passwordfile")
			case 2:
				authPages.SwitchToPage("ntlm")
			case 3:
				authPages.SwitchToPage("ntlmfile")
			case 4:
				authPages.SwitchToPage("kerberos")
			case 5:
				authPages.SwitchToPage("pem")
			case 6:
				authPages.SwitchToPage("pfx")
			}
		})

	configForm.GetFormItemByLabel("Auth Type").(*tview.DropDown).
		SetCurrentOption(AuthType)

	// SSH tunnel form
	sshForm := NewXForm()
	sshPortStr := ""
	if SSHTunnelPort != 0 {
		sshPortStr = strconv.Itoa(SSHTunnelPort)
	}
	sshAuthIdx := 0
	switch SSHTunnelAuthMethod {
	case "key":
		sshAuthIdx = 1
	case "agent":
		sshAuthIdx = 2
	}
	sshForm.
		AddInputField("SSH Host", SSHTunnelHost, 20, nil, nil).
		AddInputField("SSH Port", sshPortStr, 8, nil, nil).
		AddInputField("SSH User", SSHTunnelUser, 20, nil, nil).
		AddDropDown("SSH Auth", []string{"password", "key", "agent"}, sshAuthIdx, nil).
		AddPasswordField("SSH Password", SSHTunnelPassword, 20, '*', nil).
		AddInputField("SSH Key File", SSHTunnelKeyFile, 30, nil, nil).
		AddPasswordField("SSH Key Passphrase", SSHTunnelKeyPassphrase, 20, '*', nil).
		AddCheckbox("Ignore Host Key", SSHTunnelInsecure, nil)

	emptySSHBox := tview.NewBox()
	sshSection := tview.NewPages().
		AddPage("ssh-off", emptySSHBox, true, !SSHTunnelEnabled).
		AddPage("ssh-on", sshForm, true, SSHTunnelEnabled)

	// Add SSH Tunnel checkbox to configForm (before buttons)
	configForm.AddCheckbox("SSH Tunnel", SSHTunnelEnabled, func(checked bool) {
		if checked {
			sshSection.SwitchToPage("ssh-on")
		} else {
			sshSection.SwitchToPage("ssh-off")
		}
	})

	configForm.
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
		}).
		AddButton("Update", func() {
			// Update connection settings
			LdapServer = configForm.GetFormItemByLabel("Server").(*tview.InputField).GetText()
			LdapPort, _ = strconv.Atoi(configForm.GetFormItemByLabel("Port").(*tview.InputField).GetText())
			Ldaps = configForm.GetFormItemByLabel("LDAPS").(*tview.Checkbox).IsChecked()
			Insecure = configForm.GetFormItemByLabel("IgnoreCert").(*tview.Checkbox).IsChecked()
			SocksServer = configForm.GetFormItemByLabel("SOCKSProxy").(*tview.InputField).GetText()
			DomainName = configForm.GetFormItemByLabel("Domain").(*tview.InputField).GetText()

			// Update auth settings based on selected type
			authTypeField, _ := configForm.GetFormItemByLabel("Auth Type").(*tview.DropDown).GetCurrentOption()
			switch authTypeField {
			case 0: // Password
				LdapUsername = passwordForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
				LdapPassword = passwordForm.GetFormItemByLabel("Password").(*tview.InputField).GetText()
			case 1: // Password file
				LdapUsername = passwordFileForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
				LdapPasswordFile = passwordFileForm.GetFormItemByLabel("Password File").(*tview.InputField).GetText()
			case 2: // NTLM
				LdapUsername = ntlmForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
				NtlmHash = ntlmForm.GetFormItemByLabel("NTLM Hash").(*tview.InputField).GetText()
			case 3: // NTLM file
				LdapUsername = ntlmFileForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
				NtlmHashFile = ntlmFileForm.GetFormItemByLabel("Hash File").(*tview.InputField).GetText()
			case 4: // Kerberos
				CCachePath = kerberosForm.GetFormItemByLabel("CCACHE Path").(*tview.InputField).GetText()
				TargetSpn = kerberosForm.GetFormItemByLabel("Target SPN").(*tview.InputField).GetText()
				KdcHost = kerberosForm.GetFormItemByLabel("KDC Address").(*tview.InputField).GetText()
			case 5: // PEM
				CertFile = pemForm.GetFormItemByLabel("Certificate Path").(*tview.InputField).GetText()
				KeyFile = pemForm.GetFormItemByLabel("Key Path").(*tview.InputField).GetText()
			case 6: // PFX
				PfxFile = pfxForm.GetFormItemByLabel("PFX Path").(*tview.InputField).GetText()
			}

			AuthType = authTypeField

			// Update SSH tunnel settings
			SSHTunnelEnabled = configForm.GetFormItemByLabel("SSH Tunnel").(*tview.Checkbox).IsChecked()
			SSHTunnelHost = sshForm.GetFormItemByLabel("SSH Host").(*tview.InputField).GetText()
			sshPort, _ := validateSSHPort(sshForm.GetFormItemByLabel("SSH Port").(*tview.InputField).GetText())
			SSHTunnelPort = sshPort
			SSHTunnelUser = sshForm.GetFormItemByLabel("SSH User").(*tview.InputField).GetText()
			_, sshAuthMethod := sshForm.GetFormItemByLabel("SSH Auth").(*tview.DropDown).GetCurrentOption()
			SSHTunnelAuthMethod = sshAuthMethod
			SSHTunnelPassword = sshForm.GetFormItemByLabel("SSH Password").(*tview.InputField).GetText()
			SSHTunnelKeyFile = sshForm.GetFormItemByLabel("SSH Key File").(*tview.InputField).GetText()
			SSHTunnelKeyPassphrase = sshForm.GetFormItemByLabel("SSH Key Passphrase").(*tview.InputField).GetText()
			SSHTunnelInsecure = sshForm.GetFormItemByLabel("Ignore Host Key").(*tview.Checkbox).IsChecked()

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			reconnectLdap()
		})

	// Top row: connection settings + auth pages side by side
	topRow := tview.NewFlex().
		AddItem(configForm, 0, 1, true).
		AddItem(authPages, 0, 1, false)

	// Outer panel: top row stacked above SSH section
	configPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topRow, 0, 2, true).
		AddItem(sshSection, 0, 1, false)

	configPanel.SetBorder(true).SetTitle("Connection Configuration")

	configPanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			return nil
		}

		if event.Key() == tcell.KeyTab {
			switch app.GetFocus() {
			case configForm:
				app.SetFocus(authPages)
			case authPages:
				if SSHTunnelEnabled {
					app.SetFocus(sshForm)
				} else {
					app.SetFocus(configForm)
				}
			default:
				app.SetFocus(configForm)
			}
			return nil
		}
		return event
	})

	app.SetRoot(configPanel, true).SetFocus(configPanel)
}

func appPanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	_, isTextArea := app.GetFocus().(*tview.TextArea)
	_, isInputField := app.GetFocus().(*tview.InputField)

	if isTextArea || isInputField {
		return event
	}

	switch event.Rune() {
	case 'f', 'F':
		toggleFlagF()
	case 'e', 'E':
		toggleFlagE()
	case 'c', 'C':
		toggleFlagC()
	case 'a', 'A':
		toggleFlagA()
	case 's', 'S':
		toggleFlagS()
	case 'h', 'H':
		toggleHeader()
	case 'd', 'D':
		if lc.Flavor == ldaputils.MicrosoftADFlavor {
			toggleFlagD()
		}
	case 'l', 'L':
		openConfigForm()
	}

	switch event.Key() {
	case tcell.KeyCtrlU:
		upgradeStartTLS()
	case tcell.KeyCtrlR:
		reconnectLdap()
	}

	return event
}

// validateSSHPort parses s as an SSH port number.
// An empty string returns (0, nil). An out-of-range or non-numeric value returns an error.
func validateSSHPort(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("invalid SSH port: %q", s)
	}
	return n, nil
}

// isSSHTunnelFieldVisible reports whether SSH tunnel fields should be shown in the config form.
func isSSHTunnelFieldVisible() bool {
	return SSHTunnelEnabled
}

// showHostKeyModal displays a modal explaining that the SSH host key is unknown,
// with instructions for adding it to known_hosts.
func showHostKeyModal(host string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf(
			"Unknown SSH host key for: %s\n\n"+
				"To add it to known_hosts, run:\n"+
				"  ssh-keyscan %s >> ~/.ssh/known_hosts\n\n"+
				"Or restart godap with --ssh-ignore-host-key\n\n"+
				"Press any key to dismiss.",
			host, host,
		)).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			app.SetRoot(appPanel, true)
		})

	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		app.SetRoot(appPanel, true)
		return nil
	})

	app.SetRoot(modal, true).SetFocus(modal)
}

func readFileOrStdin(filename string, promptIfTerm string) (string, error) {
	if filename == "-" {
		return readPass(promptIfTerm), nil
	}

	content, err := os.ReadFile(filename)
	return string(content), err
}

func setupLDAPConn() error {
	updateLog("Connecting to LDAP server...", "yellow")

	if lc != nil && lc.Conn != nil {
		lc.Conn.Close()
	}

	tlsConfig = secureTlsConfig
	if Insecure {
		tlsConfig = insecureTlsConfig
	}

	var (
		currentLdapUsername string
		currentLdapPassword string
		currentNtlmHash     string
	)

	// Read password or NTLM hash from file
	var pw string
	var hash string

	if AuthType == 0 {
		currentLdapPassword = strings.TrimSpace(LdapPassword)
	} else if AuthType == 1 {
		pw, err = readFileOrStdin(LdapPasswordFile, "Password: ")

		if err != nil {
			app.Stop()
			log.Fatal(err)
		}
		currentLdapPassword = strings.TrimSpace(string(pw))
	} else if AuthType == 2 {
		currentNtlmHash = strings.TrimSpace(NtlmHash)
	} else if AuthType == 3 {
		hash, err = readFileOrStdin(NtlmHashFile, "NTLM hash: ")

		if err != nil {
			app.Stop()
			log.Fatal(err)
		}
		currentNtlmHash = strings.TrimSpace(string(hash))
	}

	// If a certificate and key pair is provided, store it
	// in the TLS config to be used for the connection
	if AuthType == 6 {
		pfxData, err := os.ReadFile(PfxFile)
		if err != nil {
			app.Stop()
			log.Fatalf("Error reading PFX file: %v", err)
		}

		// Empty password for now - can be made configurable in the future
		privateKey, cert, err := pkcs12.Decode(pfxData, "")
		if err != nil {
			app.Stop()
			log.Fatalf("Error decoding PFX: %v", err)
		}

		tlsCert := tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  privateKey,
			Leaf:        cert,
		}

		tlsConfig.Certificates = []tls.Certificate{tlsCert}
	} else if AuthType == 5 {
		cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
		if err != nil {
			app.Stop()
			log.Fatalf("Error loading certificate / key: %v", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// SSH tunnel lifecycle — close old tunnel before creating a new one.
	if activeTunnel != nil {
		activeTunnel.Close()
		activeTunnel = nil
	}

	effectiveLdapServer := LdapServer
	effectiveLdapPort := LdapPort

	if SSHTunnelEnabled && SSHTunnelHost != "" {
		port := SSHTunnelPort
		if port == 0 {
			port = 22
		}
		t, tunnelErr := sshtunnel.New(sshtunnel.Config{
			Host:                  SSHTunnelHost,
			Port:                  port,
			User:                  SSHTunnelUser,
			AuthMethod:            SSHTunnelAuthMethod,
			Password:              SSHTunnelPassword,
			KeyFile:               SSHTunnelKeyFile,
			KeyPassphrase:         SSHTunnelKeyPassphrase,
			InsecureIgnoreHostKey: SSHTunnelInsecure,
		}, LdapServer, LdapPort)
		if tunnelErr != nil {
			debug.Log("SSH tunnel failed: %v", tunnelErr)
			updateLog(fmt.Sprint(tunnelErr), "red")
			updateStateBox(statusPanel, false)
			return tunnelErr
		}
		debug.Log("SSH tunnel established on %s", t.LocalAddr())
		activeTunnel = t
		effectiveLdapServer = "127.0.0.1"
		effectiveLdapPort = t.LocalPort()
	}

	var proxyConn net.Conn = nil
	var err error

	if SocksServer != "" {
		proxyDial := socks.Dial(SocksServer)
		proxyConn, err = proxyDial("tcp", fmt.Sprintf("%s:%s", effectiveLdapServer, strconv.Itoa(effectiveLdapPort)))
		if err != nil {
			app.Stop()
			log.Fatal(fmt.Sprint(err))
		}
	}

	ldap.DefaultTimeout = time.Duration(Timeout) * time.Second

	var newLc *ldaputils.LDAPConn
	newLc, err = ldaputils.NewLDAPConn(
		effectiveLdapServer, effectiveLdapPort,
		Ldaps, tlsConfig, PagingSize, RootDN,
		proxyConn,
	)

	if err != nil {
		updateLog(fmt.Sprint(err), "red")
	} else {
		lc = newLc
		updateLog("Connection success", "green")
		isSecure := Ldaps

		switch strings.ToLower(BackendFlavor) {
		case "msad":
			lc.Flavor = ldaputils.MicrosoftADFlavor
		case "basic":
			lc.Flavor = ldaputils.BasicLDAPFlavor
		default:
			lc.GuessFlavor()
		}

		var bindType string
		if AuthType == 5 || AuthType == 6 {
			if !Ldaps {
				// If the connection was not using LDAPS, upgrade it with StartTLS
				// and then perform an ExternalBind
				err = lc.UpgradeToTLS(tlsConfig)
				if err != nil {
					app.Stop()
					log.Fatal(err)
				}

				err = lc.ExternalBind()
				if err != nil {
					app.Stop()
					log.Fatal(err)
				}
			}

			isSecure = true
			bindType = "LDAP+ClientCertificate"
		} else if AuthType == 4 {
			if _, err := os.Stat(CCachePath); err != nil {
				app.Stop()
				log.Fatal(err)
			}

			var KdcAddr string
			if KdcHost != "" {
				KdcAddr = KdcHost
			} else {
				KdcAddr = LdapServer
			}

			err = lc.KerbBindWithCCache(CCachePath, KdcAddr, DomainName, TargetSpn, "aes")
			bindType = "Kerberos"
		} else if AuthType == 2 || AuthType == 3 {
			err = lc.NTLMBindWithHash(DomainName, LdapUsername, currentNtlmHash)
			bindType = "NTLM"
		} else {
			currentLdapUsername = LdapUsername
			if !strings.Contains(LdapUsername, "@") && !strings.Contains(LdapUsername, ",") && LdapUsername != "" && DomainName != "" {
				currentLdapUsername += "@" + DomainName
			}

			err = lc.LDAPBind(currentLdapUsername, currentLdapPassword)
			bindType = "LDAP"
		}

		if err != nil {
			// Bind failed
			updateLog(fmt.Sprint(err), "red")
		} else {
			updateStateBox(tlsPanel, isSecure)
			updateLog("Bind success ("+bindType+")", "green")
		}
	}

	updateStateBox(statusPanel, err == nil)

	return err
}

func appKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	_, isTextArea := app.GetFocus().(*tview.TextArea)
	_, isInputField := app.GetFocus().(*tview.InputField)

	if isTextArea || isInputField {
		return event
	}

	if event.Key() == tcell.KeyCtrlJ {
		dstPage := (page + 1) % pages.GetPageCount()
		info.Highlight(strconv.Itoa(dstPage))
		return nil
	}

	if event.Rune() == 'q' {
		app.Stop()
		return nil
	}

	return event
}

func SetupApp() {
	tview.Styles = baseTheme

	logPanel = tview.NewTextView()
	logPanel.SetWordWrap(false).SetTitle("Last Log")
	logPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	tlsPanel = tview.NewTextView()
	tlsPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("TLS (C-u)").
		SetBorder(true)

	statusPanel = tview.NewTextView()
	statusPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Bind (C-r)").
		SetBorder(true)

	formatFlagPanel = tview.NewTextView()
	formatFlagPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Format (f)").
		SetBorder(true)

	emojiFlagPanel = tview.NewTextView()
	emojiFlagPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Emoji (e)").
		SetBorder(true)

	colorFlagPanel = tview.NewTextView()
	colorFlagPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Colors (c)").
		SetBorder(true)

	expandFlagPanel = tview.NewTextView()
	expandFlagPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Expand (a)").
		SetBorder(true)

	deletedFlagPanel = tview.NewTextView()
	deletedFlagPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Deleted (d)").
		SetBorder(true)

	sortAttrsFlagPanel = tview.NewTextView()
	sortAttrsFlagPanel.
		SetTextAlign(tview.AlignCenter).
		SetTitle("Sort (s)").
		SetBorder(true)

	// Time format setup
	TimeFormat = setupTimeFormat(TimeFormat)

	// CCache path setup
	CCachePath = os.Getenv("KRB5CCNAME")

	AuthType = getCurrentAuthType()

	err := setupLDAPConn()
	if err != nil {
		var hkErr *sshtunnel.HostKeyUnknownError
		if errors.As(err, &hkErr) {
			log.Fatalf(
				"Unknown SSH host key for %s\nRun: ssh-keyscan %s >> ~/.ssh/known_hosts\nOr use: --ssh-ignore-host-key",
				hkErr.Host, hkErr.Host,
			)
		}
		log.Fatal(err)
	}

	if RootDN == "" {
		RootDN, err = lc.FindRootDN()
		if err != nil {
			log.Fatal(err)
		}
	}

	lc.DefaultRootDN = RootDN

	// Pages setup
	// TODO: Refactor this chunk
	initExplorerPage()
	initSearchPage()
	initGroupPage()
	initDaclPage(LoadSchema)
	initGPOPage()
	initADIDNSPage()
	initHelpPage()

	var pageVars []GodapPage
	if lc.Flavor == ldaputils.MicrosoftADFlavor {
		pageVars = []GodapPage{
			{0, explorerPage, "Explorer"},
			{1, searchPage, "Search"},
			{2, groupPage, "Groups"},
			{3, daclPage, "DACLs"},
			{4, gpoPage, "GPOs"},
			{5, dnsPage, "ADIDNS"},
			{6, helpPage, "Help"},
		}
	} else if lc.Flavor == ldaputils.BasicLDAPFlavor {
		pageVars = []GodapPage{
			{0, explorerPage, "Explorer"},
			{1, searchPage, "Search"},
			{2, groupPage, "Groups"},
			{3, helpPage, "Help"},
		}
	}

	for _, page := range pageVars {
		pages.AddPage("page-"+strconv.Itoa(page.idx), page.prim, true, false)
	}

	pages.ShowPage("page-0")

	info.SetDynamicColors(true).
		SetRegions(true).
		SetWrap(false).
		SetHighlightedFunc(func(added, removed, remaining []string) {
			nextPage := "0"
			if len(added) > 0 {
				nextPage = added[0]
				pages.SwitchToPage("page-" + nextPage)
				page, _ = strconv.Atoi(nextPage)
				setPageFocus()
			} else {
				info.Highlight(nextPage)
			}
		})

	for idx, page := range pageVars {
		fmt.Fprintf(info, `%d ["%s"][darkcyan]%s[white][""]  `, idx+1, strconv.Itoa(idx), page.title)
	}

	info.Highlight("0")

	headerPanel = tview.NewFlex().
		AddItem(tlsPanel, 0, 1, false).
		AddItem(statusPanel, 0, 1, false).
		AddItem(formatFlagPanel, 0, 1, false).
		AddItem(colorFlagPanel, 0, 1, false).
		AddItem(expandFlagPanel, 0, 1, false).
		AddItem(sortAttrsFlagPanel, 0, 1, false).
		AddItem(emojiFlagPanel, 0, 1, false)

	if lc.Flavor == ldaputils.MicrosoftADFlavor {
		headerPanel.AddItem(deletedFlagPanel, 0, 1, false)
	}

	appPanel = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(info, 1, 1, false).
		AddItem(logPanel, 3, 0, false).
		AddItem(headerPanel, 3, 0, false).
		AddItem(pages, 0, 8, false)
	appPanel.SetInputCapture(appPanelKeyHandler)

	app.EnableMouse(true)
	app.SetInputCapture(appKeyHandler)

	updateStateBox(statusPanel, true)
	updateStateBox(formatFlagPanel, FormatAttrs)
	updateStateBox(colorFlagPanel, Colors)
	updateStateBox(emojiFlagPanel, Emojis)
	updateStateBox(expandFlagPanel, ExpandAttrs)
	updateStateBox(deletedFlagPanel, Deleted)
	updateSortStateBox(AttrSort)

	if err := app.SetRoot(appPanel, true).SetFocus(treePanel).Run(); err != nil {
		log.Fatal(err)
	}
}

// setupTimeFormat returns the time format string based on the given format code.
// The format code can be one of the following:
// - "EU" or empty string: returns the format "02/01/2006 15:04:05" (day/month/year hour:minute:second)
// - "US": returns the format "01/02/2006 15:04:05" (month/day/year hour:minute:second)
// - "ISO8601": returns the format "2006-01-02 15:04:05" (year-month-day hour:minute:second)
// If the format code is not recognized, it assumed to be a golang time format and is returned unchanged.
func setupTimeFormat(f string) string {
	switch strings.ToUpper(f) {
	case "EU", "":
		return "02/01/2006 15:04:05"
	case "US":
		return "01/02/2006 15:04:05"
	case "ISO8601":
		return "2006-01-02 15:04:05"
	}
	return f
}

func updateStateBox(target *tview.TextView, control bool) {
	go app.QueueUpdateDraw(func() {
		if control {
			target.SetText("ON")
			target.SetTextColor(tcell.GetColor("green"))
		} else {
			target.SetText("OFF")
			target.SetTextColor(tcell.GetColor("red"))
		}
	})
}

func updateLog(msg string, color string) {
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02 15:04:05")

	logPanel.SetText("[" + formattedTime + "] " + msg).SetTextColor(tcell.GetColor(color))
}

func handleLDAPError(err error) {
	msg := fmt.Sprint(err)
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		msg += " - Maybe try reconnecting with Ctrl+R"
		updateStateBox(statusPanel, false)
	}
	updateLog(msg, "red")
}

func setPageFocus() {
	switch page {
	case 0:
		app.SetFocus(treePanel)
	case 1:
		app.SetFocus(searchTreePanel)
	case 2:
		app.SetFocus(membersPanel)
	case 3:
		app.SetFocus(daclEntriesPanel)
	case 4:
		app.SetFocus(gpoListPanel)
	case 5:
		app.SetFocus(dnsTreePanel)
	case 6:
		app.SetFocus(keybindingsPanel)
	}
}
