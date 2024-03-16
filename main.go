package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Macmod/godap/v2/utils"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"h12.io/socks"
)

var (
	ldapServer       string
	ldapPort         int
	ldapUsername     string
	ldapPassword     string
	ldapPasswordFile string
	ntlmHash         string
	ntlmHashFile     string
	ntlmDomain       string
	socksServer      string

	emojis       bool
	colors       bool
	formatAttrs  bool
	expandAttrs  bool
	cacheEntries bool
	loadSchema   bool
	pagingSize   uint32
	insecure     bool
	ldaps        bool
	searchFilter string
	rootDN       string

	tlsConfig *tls.Config
	lc        *utils.LDAPConn
	err       error

	page       int
	showHeader bool
)

var (
	appPanel    *tview.Flex
	headerPanel *tview.Flex
	rootNode    *tview.TreeNode
	logPanel    *tview.TextView

	formatFlagPanel *tview.TextView
	emojiFlagPanel  *tview.TextView
	colorFlagPanel  *tview.TextView
	expandFlagPanel *tview.TextView
	tlsPanel        *tview.TextView
	statusPanel     *tview.TextView
)

var attrLimit int

var app = tview.NewApplication()

var pages = tview.NewPages()

var info = tview.NewTextView()

var insecureTlsConfig = &tls.Config{InsecureSkipVerify: true}

var secureTlsConfig = &tls.Config{InsecureSkipVerify: false}

func updateStateBox(target *tview.TextView, control bool) {
	go func() {
		app.QueueUpdateDraw(func() {
			if control {
				target.SetText("ON")
				target.SetTextColor(tcell.GetColor("green"))
			} else {
				target.SetText("OFF")
				target.SetTextColor(tcell.GetColor("red"))
			}
		})
	}()
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
		app.SetFocus(groupMembersPanel)
	case 3:
		app.SetFocus(daclEntriesPanel)
	case 4:
		app.SetFocus(keybindingsPanel)
	}
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

func appPanelKeyHandler(event *tcell.EventKey) *tcell.EventKey {
	_, isTextArea := app.GetFocus().(*tview.TextArea)
	_, isInputField := app.GetFocus().(*tview.InputField)

	if isTextArea || isInputField {
		return event
	}

	switch event.Rune() {
	case 'f', 'F':
		formatAttrs = !formatAttrs
		updateStateBox(formatFlagPanel, formatAttrs)

		node := treePanel.GetCurrentNode()
		if node != nil {
			err = reloadAttributesPanel(node, cacheEntries)
		}
	case 'e', 'E':
		emojis = !emojis
		emojiFlagPanel.SetText("Emojis: " + strconv.FormatBool(emojis))
		updateStateBox(emojiFlagPanel, emojis)
		updateEmojis()
	case 'c', 'C':
		colors = !colors
		updateStateBox(colorFlagPanel, colors)
		node := treePanel.GetCurrentNode()
		if node != nil {
			reloadAttributesPanel(node, cacheEntries)
		}
	case 'a', 'A':
		expandAttrs = !expandAttrs
		updateStateBox(expandFlagPanel, expandAttrs)
		node := treePanel.GetCurrentNode()
		if node != nil {
			reloadAttributesPanel(node, cacheEntries)
		}
	case 'h', 'H':
		showHeader = !showHeader
		if showHeader {
			appPanel.RemoveItem(headerPanel)
		} else {
			appPanel.RemoveItem(pages)
			appPanel.AddItem(headerPanel, 3, 0, false)
			appPanel.AddItem(pages, 0, 8, false)
		}
	case 'l', 'L':
		credsForm := tview.NewForm()
		credsForm.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event.Key() == tcell.KeyEscape {
				app.SetRoot(appPanel, true).SetFocus(appPanel)
				return nil
			}
			return event
		})

		credsForm = credsForm.
			AddInputField("Server", ldapServer, 20, nil, nil).
			AddInputField("Port", strconv.Itoa(ldapPort), 20, nil, nil).
			AddInputField("Username", ldapUsername, 20, nil, nil).
			AddPasswordField("Password", ldapPassword, 20, '*', nil).
			AddCheckbox("LDAPS", ldaps, nil).
			AddCheckbox("IgnoreCert", insecure, nil).
			AddInputField("SOCKSProxy", socksServer, 20, nil, nil).
			SetFieldBackgroundColor(tcell.GetColor("black")).
			AddButton("Go Back", func() {
				app.SetRoot(appPanel, false).SetFocus(treePanel)
			}).
			AddButton("Update", func() {
				ldapServer = credsForm.GetFormItemByLabel("Server").(*tview.InputField).GetText()
				ldapPort, _ = strconv.Atoi(credsForm.GetFormItemByLabel("Port").(*tview.InputField).GetText())
				ldapUsername = credsForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
				ldapPassword = credsForm.GetFormItemByLabel("Password").(*tview.InputField).GetText()

				ldaps = credsForm.GetFormItemByLabel("LDAPS").(*tview.Checkbox).IsChecked()
				insecure = credsForm.GetFormItemByLabel("IgnoreCert").(*tview.Checkbox).IsChecked()

				socksServer = credsForm.GetFormItemByLabel("SOCKSProxy").(*tview.InputField).GetText()

				app.SetRoot(appPanel, false).SetFocus(treePanel)
			})

		credsForm.SetTitle("Connection Config").SetBorder(true)
		app.SetRoot(credsForm, true).SetFocus(credsForm)
	}

	switch event.Key() {
	case tcell.KeyCtrlU:
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
	case tcell.KeyCtrlR:
		// TODO: Check possible race conditions
		go setupLDAPConn()
	}

	return event
}

func setupLDAPConn() error {
	if lc != nil && lc.Conn != nil {
		lc.Conn.Close()
	}

	tlsConfig = secureTlsConfig
	if insecure {
		tlsConfig = insecureTlsConfig
	}

	var proxyConn net.Conn = nil
	var err error = nil

	if socksServer != "" {
		proxyDial := socks.Dial(socksServer)
		proxyConn, err = proxyDial("tcp", fmt.Sprintf("%s:%s", ldapServer, strconv.Itoa(ldapPort)))
		if err != nil {
			updateLog(fmt.Sprint(err), "red")
			return err
		}
	}

	lc, err = utils.NewLDAPConn(
		ldapServer, ldapPort,
		ldaps, tlsConfig, pagingSize,
		proxyConn,
	)

	if err != nil {
		updateLog(fmt.Sprint(err), "red")
	} else {
		updateLog("Connection success", "green")

		var bindType string
		if ntlmHash != "" {
			err = lc.NTLMBindWithHash(ntlmDomain, ldapUsername, ntlmHash)
			bindType = "NTLM"
		} else {
			err = lc.LDAPBind(ldapUsername, ldapPassword)
			bindType = "LDAP"
		}

		if err != nil {
			updateLog(fmt.Sprint(err), "red")
		} else {
			updateLog("Bind success ("+bindType+")", "green")
		}
	}

	updateStateBox(statusPanel, err == nil)
	if ldaps {
		updateStateBox(tlsPanel, err == nil)
	}

	return err
}

func setupApp() {
	logPanel = tview.NewTextView()
	logPanel.SetTitle("Last Log")
	logPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	tlsPanel = tview.NewTextView()
	tlsPanel.SetTitle("TLS")
	tlsPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	statusPanel = tview.NewTextView()
	statusPanel.SetTitle("Conn")
	statusPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	formatFlagPanel = tview.NewTextView()
	formatFlagPanel.SetTitle("Format")
	formatFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	emojiFlagPanel = tview.NewTextView()
	emojiFlagPanel.SetTitle("Emoji")
	emojiFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	colorFlagPanel = tview.NewTextView()
	colorFlagPanel.SetTitle("Colors")
	colorFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	expandFlagPanel = tview.NewTextView()
	expandFlagPanel.SetTitle("Expand")
	expandFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

	err := setupLDAPConn()
	if err != nil {
		log.Fatal(err)
	}

	if rootDN == "" {
		rootDN, err = lc.FindRootDN()
		if err != nil {
			log.Fatal(err)
		}
	}
	lc.RootDN = rootDN

	// Pages setup
	initExplorerPage()
	initSearchPage()
	initGroupPage()
	initDaclPage(loadSchema)
	initHelpPage()

	pages.AddPage("page-0", explorerPage, true, true)

	pages.AddPage("page-1", searchPage, true, false)

	pages.AddPage("page-2", groupPage, true, false)

	pages.AddPage("page-3", daclPage, true, false)

	pages.AddPage("page-4", helpPage, true, false)

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

	fmt.Fprintf(info, `%d ["%s"][darkcyan]%s[white][""]  `, 1, "0", "LDAP Explorer")
	fmt.Fprintf(info, `%d ["%s"][darkcyan]%s[white][""]  `, 2, "1", "Object Search")
	fmt.Fprintf(info, `%d ["%s"][darkcyan]%s[white][""]  `, 3, "2", "Group Lookups")
	fmt.Fprintf(info, `%d ["%s"][darkcyan]%s[white][""]  `, 4, "3", "DACL Editor")
	fmt.Fprintf(info, `%d ["%s"][darkcyan]%s[white][""]  `, 5, "4", "Help")

	info.Highlight("0")

	headerPanel = tview.NewFlex().
		AddItem(tlsPanel, 0, 1, false).
		AddItem(statusPanel, 0, 1, false).
		AddItem(formatFlagPanel, 0, 1, false).
		AddItem(colorFlagPanel, 0, 1, false).
		AddItem(expandFlagPanel, 0, 1, false).
		AddItem(emojiFlagPanel, 0, 1, false)

	appPanel = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(info, 1, 1, false).
		AddItem(logPanel, 3, 0, false).
		AddItem(headerPanel, 3, 0, false).
		AddItem(pages, 0, 8, false)
	appPanel.SetInputCapture(appPanelKeyHandler)

	app.EnableMouse(true)
	app.SetInputCapture(appKeyHandler)

	updateStateBox(tlsPanel, ldaps)
	updateStateBox(statusPanel, true)
	updateStateBox(formatFlagPanel, formatAttrs)
	updateStateBox(colorFlagPanel, colors)
	updateStateBox(emojiFlagPanel, emojis)
	updateStateBox(expandFlagPanel, expandAttrs)

	if err := app.SetRoot(appPanel, true).SetFocus(treePanel).Run(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	tview.Styles = baseTheme

	godapVer := "Godap v2.2.0"

	rootCmd := &cobra.Command{
		Use:   "godap <server address>",
		Short: "A complete TUI for LDAP.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ldapServer = args[0]

			if ldapPasswordFile != "" {
				pw, err := os.ReadFile(ldapPasswordFile)
				if err != nil {
					log.Fatal(err)
				}
				ldapPassword = strings.TrimSpace(string(pw))
			}
			if ntlmHashFile != "" {
				hash, err := os.ReadFile(ntlmHashFile)
				if err != nil {
					log.Fatal(err)
				}
				ntlmHash = strings.TrimSpace(string(hash))
			}

			setupApp()
		},
	}

	rootCmd.Flags().IntVarP(&ldapPort, "port", "P", 389, "LDAP server port")
	rootCmd.Flags().StringVarP(&ldapUsername, "username", "u", "", "LDAP username")
	rootCmd.Flags().StringVarP(&ldapPassword, "password", "p", "", "LDAP password")
	rootCmd.Flags().StringVarP(&ldapPasswordFile, "passfile", "", "", "Path to a file containing the LDAP password")
	rootCmd.Flags().StringVarP(&ntlmDomain, "domain", "d", "", "Domain for NTLM bind")
	rootCmd.Flags().StringVarP(&ntlmHash, "hashes", "H", "", "NTLM hash")
	rootCmd.Flags().StringVarP(&ntlmHashFile, "hashfile", "", "", "Path to a file containing the NTLM hash")
	rootCmd.Flags().StringVarP(&rootDN, "rootDN", "r", "", "Initial root DN")
	rootCmd.Flags().StringVarP(&searchFilter, "filter", "f", "(objectClass=*)", "Initial LDAP search filter")
	rootCmd.Flags().BoolVarP(&emojis, "emojis", "E", true, "Prefix objects with emojis")
	rootCmd.Flags().BoolVarP(&colors, "colors", "C", true, "Colorize objects")
	rootCmd.Flags().BoolVarP(&formatAttrs, "format", "F", true, "Format attributes into human-readable values")
	rootCmd.Flags().BoolVarP(&expandAttrs, "expand", "A", true, "Expand multi-value attributes")
	rootCmd.Flags().IntVarP(&attrLimit, "limit", "L", 20, "Number of attribute values to render for multi-value attributes when -expand is set true")
	rootCmd.Flags().BoolVarP(&cacheEntries, "cache", "M", true, "Keep loaded entries in memory while the program is open and don't query them again")
	rootCmd.Flags().BoolVarP(&loadSchema, "schema", "k", false, "Load schema GUIDs from the LDAP server during initialization")
	rootCmd.Flags().Uint32VarP(&pagingSize, "paging", "G", 800, "Default paging size for regular queries")
	rootCmd.Flags().BoolVarP(&insecure, "insecure", "I", false, "Skip TLS verification for LDAPS/StartTLS")
	rootCmd.Flags().BoolVarP(&ldaps, "ldaps", "S", false, "Use LDAPS for initial connection")
	rootCmd.Flags().StringVarP(&socksServer, "socks", "x", "", "Use a SOCKS proxy for initial connection")

	versionCmd := &cobra.Command{
		Use:                   "version",
		Short:                 "Print the version number of the application",
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(godapVer)
		},
	}

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
