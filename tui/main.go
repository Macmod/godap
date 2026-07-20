package tui

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
	"github.com/RedTeamPentesting/adauth"
	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/term"
)

var GodapVer = "Godap v2.12.0"
var (
	LdapServer       string
	LdapPort         int
	TimeOffset       int
	LdapUsername     string
	LdapPassword     string
	LdapPasswordFile string
	NtlmHash         string
	NtlmHashFile     string
	AESKey           string
	DomainName       string
	SocksServer      string
	KdcHost          string
	CustomDNS        string
	TimeFormat       string
	CertFile         string
	KeyFile          string
	PfxFile          string
	CCachePath       string
	BackendFlavor    string

	Kerberos      bool
	SimpleBind    bool
	ForceDNSTCP   bool
	NoProxyDNS    bool
	Emojis        bool
	Colors        bool
	FormatAttrs   bool
	ExpandAttrs   bool
	AttrSort      string
	AttrLimit     int
	CacheEntries  bool
	Deleted       bool
	LoadSchema    bool
	PagingSize    uint32
	Timeout       int32
	Insecure      bool
	Ldaps         bool
	SearchFilter  string
	RootDN        string
	ShowHeader    bool
	AuthMechanism string
	ExportDir     string

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

	tlsConfig *tls.Config
	lc        = &ldaputils.LDAPConn{}
	err       error
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
		setupLDAPConn()
	})
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
		AddInputField("Domain", DomainName, 20, nil, nil)

	authTypeOptions := make([]string, len(authMechanisms))
	for i, m := range authMechanisms {
		authTypeOptions[i] = m.Label
	}
	configForm.AddDropDown("Auth Type", authTypeOptions, 0, nil)

	// One page per auth mechanism, built entirely from its Fields list -
	// every mechanism in authMechanisms is automatically representable here,
	// with no per-mechanism form to hand-maintain.
	authPages := tview.NewPages()
	mechForms := make(map[string]*XForm, len(authMechanisms))
	for i, m := range authMechanisms {
		form := buildFieldsPage(m.Fields)
		mechForms[m.ID] = form
		authPages.AddPage(m.ID, form, true, i == 0)
	}

	// Handle auth type selection
	configForm.GetFormItemByLabel("Auth Type").(*tview.DropDown).
		SetSelectedFunc(func(text string, index int) {
			authPages.SwitchToPage(authMechanisms[index].ID)
		})

	currentMechanism := indexOfMechanism(AuthMechanism)
	configForm.GetFormItemByLabel("Auth Type").(*tview.DropDown).
		SetCurrentOption(currentMechanism)
	authPages.SwitchToPage(authMechanisms[currentMechanism].ID)

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

			// Update auth settings from whichever mechanism page is active -
			// only the fields that mechanism declares are read back, so
			// switching mechanisms never clobbers a field it doesn't show.
			authTypeField, _ := configForm.GetFormItemByLabel("Auth Type").(*tview.DropDown).GetCurrentOption()
			mech := authMechanisms[authTypeField]
			applyFieldsPage(mechForms[mech.ID], mech.Fields)

			AuthMechanism = mech.ID

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

func readFileOrStdin(filename string, promptIfTerm string) (string, error) {
	if filename == "-" {
		return readPass(promptIfTerm), nil
	}

	content, err := os.ReadFile(filename)
	return string(content), err
}

// buildDialer returns the dialer used for LDAP TCP traffic and Kerberos KDC
// traffic alike, uniformly covering SOCKS proxying for every auth mode
// (godap's manual h12.io/socks dial previously only covered the initial LDAP
// TCP connection, leaving Kerberos KDC traffic unproxied).
func buildDialer(socksServer string) adauth.Dialer {
	return adauth.DialerWithSOCKS5ProxyIfSet(socksServer, &net.Dialer{Timeout: 10 * time.Second})
}

// buildResolver constructs the custom DNS resolver for --dns/--dns-tcp, if
// set. Deliberately built per-invocation and injected via adauth's Resolver
// fields rather than mutating net.DefaultResolver globally. --no-proxy-dns
// excludes the DNS traffic itself from the SOCKS proxy while everything else
// (LDAP, Kerberos) still goes through it.
func buildResolver() adauth.Resolver {
	if CustomDNS == "" {
		return nil
	}

	dnsAddr := CustomDNS
	if _, _, splitErr := net.SplitHostPort(dnsAddr); splitErr != nil {
		dnsAddr = net.JoinHostPort(dnsAddr, "53")
	}

	network := "udp"
	if ForceDNSTCP {
		network = "tcp"
	}

	dnsSocksServer := SocksServer
	if NoProxyDNS {
		dnsSocksServer = ""
	}
	dialer := adauth.AsContextDialer(buildDialer(dnsSocksServer))

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dnsAddr)
		},
	}
}

// connectionParams assembles the connection-level settings shared by every
// bind mode from the current flag values.
func connectionParams() ldaputils.ConnectParams {
	scheme := "ldap"
	if Ldaps {
		scheme = "ldaps"
	}

	return ldaputils.ConnectParams{
		Server:     LdapServer,
		Port:       LdapPort,
		Scheme:     scheme,
		Insecure:   Insecure,
		Timeout:    time.Duration(Timeout) * time.Second,
		PagingSize: PagingSize,
		RootDN:     RootDN,
		KdcHost:    KdcHost,
		Dialer:     buildDialer(SocksServer),
		Resolver:   buildResolver(),
	}
}

// ldapIdentity builds the identity string used for a simple LDAP bind,
// matching godap's pre-migration behavior: an already-qualified bind DN,
// UPN, or bare username is passed through unchanged, and a plain username is
// qualified with -d/--domain if one was given.
func ldapIdentity() string {
	identity := LdapUsername
	if identity != "" && DomainName != "" && !strings.Contains(identity, "@") && !strings.Contains(identity, ",") {
		identity += "@" + DomainName
	}
	return identity
}

func setupLDAPConn() error {
	updateLog("Connecting to LDAP server...", "yellow")

	if lc != nil && lc.Conn != nil {
		lc.Conn.Close()
	}

	// tlsConfig is also used by upgradeStartTLS (Ctrl+U), independent of the
	// bind mode below.
	tlsConfig = secureTlsConfig
	if Insecure {
		tlsConfig = insecureTlsConfig
	}

	ctx := context.Background()

	// A domain embedded in -u/--username (user@domain or DOMAIN\user) counts
	// as -d/--domain when the latter wasn't given explicitly - both for DC
	// discovery below and so NTLM/Kerberos binds get a bare Username with
	// Domain set separately, as adauth's Credential expects, instead of a
	// domain-qualified Username with an empty Domain.
	if DomainName == "" {
		if domain, user := splitDomainAndUsername(LdapUsername); domain != "" {
			DomainName = domain
			LdapUsername = user
		}
	}

	if LdapServer == "" {
		if DomainName == "" {
			err = fmt.Errorf("no target server given and no -d/--domain to discover one from")
			updateLog(fmt.Sprint(err), "red")
			updateStateBox(statusPanel, false)
			return err
		}

		discovered, discErr := ldaputils.ResolveDCServer(ctx, DomainName, buildResolver())
		if discErr != nil {
			err = fmt.Errorf("discover domain controller for %q: %w", DomainName, discErr)
			updateLog(fmt.Sprint(err), "red")
			updateStateBox(statusPanel, false)
			return err
		}
		LdapServer = discovered
	}

	params := connectionParams()

	mech := mechanismByID(AuthMechanism)
	newLc, bindType, secure, err := mech.Bind(ctx, params)

	if err != nil {
		updateLog(fmt.Sprint(err), "red")
		updateStateBox(statusPanel, false)
		return err
	}

	lc = newLc
	updateLog("Connection success", "green")

	switch strings.ToLower(BackendFlavor) {
	case "msad":
		lc.Flavor = ldaputils.MicrosoftADFlavor
	case "basic":
		lc.Flavor = ldaputils.BasicLDAPFlavor
	default:
		lc.GuessFlavor()
	}

	updateStateBox(tlsPanel, Ldaps || secure)
	updateLog("Bind success ("+bindType+")", "green")
	updateStateBox(statusPanel, true)

	return nil
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

	AuthMechanism = resolveMechanismID()

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
