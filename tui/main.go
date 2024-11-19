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

var GodapVer = "Godap v2.8.1"

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

func openConfigForm() {
	credsForm := NewXForm()
	credsForm.
		AddInputField("Server", LdapServer, 20, nil, nil).
		AddInputField("Port", strconv.Itoa(LdapPort), 20, nil, nil).
		AddInputField("Username", LdapUsername, 20, nil, nil).
		AddPasswordField("Password", LdapPassword, 20, '*', nil).
		AddCheckbox("LDAPS", Ldaps, nil).
		AddCheckbox("IgnoreCert", Insecure, nil).
		AddInputField("SOCKSProxy", SocksServer, 20, nil, nil).
		AddButton("Go Back", func() {
			app.SetRoot(appPanel, false).SetFocus(treePanel)
		}).
		AddButton("Update", func() {
			LdapServer = credsForm.GetFormItemByLabel("Server").(*tview.InputField).GetText()
			LdapPort, _ = strconv.Atoi(credsForm.GetFormItemByLabel("Port").(*tview.InputField).GetText())
			LdapUsername = credsForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
			LdapPassword = credsForm.GetFormItemByLabel("Password").(*tview.InputField).GetText()

			Ldaps = credsForm.GetFormItemByLabel("LDAPS").(*tview.Checkbox).IsChecked()
			Insecure = credsForm.GetFormItemByLabel("IgnoreCert").(*tview.Checkbox).IsChecked()

			SocksServer = credsForm.GetFormItemByLabel("SOCKSProxy").(*tview.InputField).GetText()

			app.SetRoot(appPanel, false).SetFocus(treePanel)

			reconnectLdap()
		})

	credsForm.SetTitle("Connection Config").SetBorder(true)
	//assignFormTheme(credsForm)

	credsForm.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.SetRoot(appPanel, true).SetFocus(appPanel)
			return nil
		}
		return event
	})

	app.SetRoot(credsForm, true).SetFocus(credsForm)
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

	// If a certificate and key pair is provided, store it
	// in the TLS config to be used for the connection
	if CertFile != "" && KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
		if err != nil {
			log.Fatalf("Error loading certificate / key: %v", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	} else if PfxFile != "" {
		pfxData, err := os.ReadFile(PfxFile)
		if err != nil {
			log.Fatalf("Error reading PFX file: %v", err)
		}

		// Empty password for now - can be made configurable in the future
		privateKey, cert, err := pkcs12.Decode(pfxData, "")
		if err != nil {
			log.Fatalf("Error decoding PFX: %v", err)
		}

		tlsCert := tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  privateKey,
			Leaf:        cert,
		}

		tlsConfig.Certificates = []tls.Certificate{tlsCert}
	}

	var proxyConn net.Conn = nil
	var err error = nil

	if SocksServer != "" {
		proxyDial := socks.Dial(SocksServer)
		proxyConn, err = proxyDial("tcp", fmt.Sprintf("%s:%s", LdapServer, strconv.Itoa(LdapPort)))
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return err
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
		updateStateBox(tlsPanel, Ldaps)

		var bindType string
		if tlsConfig.Certificates != nil {
			if !Ldaps {
				// If the connection was not using LDAPS, upgrade it with StartTLS
				// and then perform an ExternalBind
				err = lc.UpgradeToTLS(tlsConfig)
				if err != nil {
					log.Fatal(err)
				}

				err = lc.ExternalBind()
				if err != nil {
					log.Fatal(err)
				}
			}

			updateStateBox(tlsPanel, true)
			bindType = "LDAP+ClientCertificate"
		} else if Kerberos {
			ccachePath := os.Getenv("KRB5CCNAME")

			var KdcAddr string
			if KdcHost != "" {
				KdcAddr = KdcHost
			} else {
				KdcAddr = LdapServer
			}

			err = lc.KerbBindWithCCache(ccachePath, KdcAddr, DomainName, TargetSpn, "aes")
			bindType = "Kerberos"
		} else if NtlmHash != "" {
			err = lc.NTLMBindWithHash(DomainName, LdapUsername, NtlmHash)
			bindType = "NTLM"
		} else {
			if !strings.Contains(LdapUsername, "@") && DomainName != "" {
				LdapUsername += "@" + DomainName
			}

			err = lc.LDAPBind(LdapUsername, LdapPassword)
			bindType = "LDAP"
		}

		if err != nil {
			updateLog(fmt.Sprint(err), "red")
		} else {
			updateLog("Bind success ("+bindType+")", "green")
		}
	}

	updateStateBox(statusPanel, err == nil)
	updateStateBox(tlsPanel, Ldaps)

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
