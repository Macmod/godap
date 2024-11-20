package tui

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
	"h12.io/socks"
	"software.sslmate.com/src/go-pkcs12"
)

var GodapVer = "Godap v2.9.0"

var (
	LdapServer       string
	LdapPort         int
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

	Kerberos     bool
	Emojis       bool
	Colors       bool
	FormatAttrs  bool
	ExpandAttrs  bool
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

	page int
)

var (
	appPanel    *tview.Flex
	headerPanel *tview.Flex
	rootNode    *tview.TreeNode
	logPanel    *tview.TextView

	statusPanel      *tview.TextView
	tlsPanel         *tview.TextView
	formatFlagPanel  *tview.TextView
	emojiFlagPanel   *tview.TextView
	colorFlagPanel   *tview.TextView
	expandFlagPanel  *tview.TextView
	deletedFlagPanel *tview.TextView

	tlsConfig *tls.Config
	lc        *ldaputils.LDAPConn
	err       error
)

type GodapPage struct {
	prim  tview.Primitive
	title string
}

var app = tview.NewApplication()

var pages = tview.NewPages()

var info = tview.NewTextView()

var insecureTlsConfig = &tls.Config{InsecureSkipVerify: true}

var secureTlsConfig = &tls.Config{InsecureSkipVerify: false}

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

func toggleFlagA() {
	ExpandAttrs = !ExpandAttrs
	updateStateBox(expandFlagPanel, ExpandAttrs)
	nodeExplorer := treePanel.GetCurrentNode()
	if nodeExplorer != nil {
		reloadExplorerAttrsPanel(nodeExplorer, CacheEntries)
	}

	nodeSearch := searchTreePanel.GetCurrentNode()
	if nodeSearch != nil {
		reloadSearchAttrsPanel(nodeSearch, CacheEntries)
	}
}

func toggleFlagD() {
	Deleted = !Deleted
	updateStateBox(deletedFlagPanel, Deleted)
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

func upgradeStartTLS() {
	// TODO: Check possible race conditions
	go func() {
		err = lc.UpgradeToTLS(tlsConfig)
		if err != nil {
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
		setupLDAPConn()
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

			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			reconnectLdap()
		})

	// Create configPanel container for both forms
	configPanel := tview.NewFlex().
		AddItem(configForm, 0, 1, true).
		AddItem(authPages, 0, 1, false)

	configPanel.SetBorder(true).SetTitle("Connection Configuration")

	//assignFormTheme(credsForm)

	configPanel.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(currentFocus)
			return nil
		}

		if event.Key() == tcell.KeyTab {
			if app.GetFocus() == configForm {
				app.SetFocus(authPages)
			} else {
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
	case 'h', 'H':
		toggleHeader()
	case 'd', 'D':
		toggleFlagD()
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

	// Auth stuffs
	if AuthType == 1 {
		pw, err := os.ReadFile(LdapPasswordFile)
		if err != nil {
			app.Stop()
			log.Fatal(err)
		}
		currentLdapPassword = strings.TrimSpace(string(pw))
	} else {
		currentLdapPassword = LdapPassword
	}

	if AuthType == 3 {
		hash, err := os.ReadFile(NtlmHashFile)
		if err != nil {
			app.Stop()
			log.Fatal(err)
		}
		currentNtlmHash = strings.TrimSpace(string(hash))
	} else {
		currentNtlmHash = NtlmHash
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

	var proxyConn net.Conn = nil
	var err error = nil

	if SocksServer != "" {
		proxyDial := socks.Dial(SocksServer)
		proxyConn, err = proxyDial("tcp", fmt.Sprintf("%s:%s", LdapServer, strconv.Itoa(LdapPort)))
		if err != nil {
			app.Stop()
			log.Fatal(fmt.Sprint(err))
		}
	}

	ldap.DefaultTimeout = time.Duration(Timeout) * time.Second

	lc, err = ldaputils.NewLDAPConn(
		LdapServer, LdapPort,
		Ldaps, tlsConfig, PagingSize, RootDN,
		proxyConn,
	)

	if err != nil {
		updateLog(fmt.Sprint(err), "red")
	} else {
		updateLog("Connection success", "green")
		isSecure := Ldaps

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
			if !strings.Contains(currentLdapUsername, "@") && DomainName != "" {
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
	logPanel.SetTitle("Last Log")
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

	// Time format setup
	TimeFormat = setupTimeFormat(TimeFormat)

	// CCache path setup
	CCachePath = os.Getenv("KRB5CCNAME")

	AuthType = getCurrentAuthType()

	err := setupLDAPConn()
	if err != nil {
		log.Fatal(err)
	}

	if RootDN == "" {
		RootDN, err = lc.FindRootDN()
		if err != nil {
			log.Fatal(err)
		}
	}

	lc.DefaultRootDN = RootDN
	lc.RootDN = RootDN

	// Pages setup
	// TODO: Refactor this chunk
	initExplorerPage()
	initSearchPage()
	initGroupPage()
	initDaclPage(LoadSchema)
	initGPOPage()
	initADIDNSPage()
	initHelpPage()

	pageVars := []GodapPage{
		{explorerPage, "Explorer"},
		{searchPage, "Search"},
		{groupPage, "Groups"},
		{daclPage, "DACLs"},
		{gpoPage, "GPOs"},
		{dnsPage, "ADIDNS"},
		{helpPage, "Help"},
	}

	for idx, page := range pageVars {
		pages.AddPage("page-"+strconv.Itoa(idx), page.prim, true, false)
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
		AddItem(emojiFlagPanel, 0, 1, false).
		AddItem(deletedFlagPanel, 0, 1, false)

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
