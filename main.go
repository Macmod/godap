package main

import (
    "crypto/tls"
    "strconv"
    "time"
    "flag"
    "fmt"
    "log"
    "os"
    "github.com/go-ldap/ldap/v3"
    "github.com/rivo/tview"
    "github.com/gdamore/tcell/v2"
    "github.com/Macmod/godap/utils"
)

var (
    ldapServer   string
    ldapPort     int
    ldapUsername string
    ldapPassword string

    emojis       bool
    colors       bool
    formatAttrs  bool
    expandAttrs  bool
    cacheEntries bool
    insecure     bool
    ldaps        bool
    searchFilter string
    rootDN       string
    conn         *ldap.Conn
    err          error

    page         int
    showHeader   bool
)

var (
    appPanel     *tview.Flex
    headerPanel  *tview.Flex
    rootNode     *tview.TreeNode
    logPanel     *tview.TextView

    formatFlagPanel *tview.TextView
    emojiFlagPanel  *tview.TextView
    colorFlagPanel  *tview.TextView
    expandFlagPanel *tview.TextView
    tlsPanel        *tview.TextView
    statusPanel     *tview.TextView
)

var attrLimit int

var pageCount = 4

var insecureTlsConfig = &tls.Config{InsecureSkipVerify: true}

var secureTlsConfig = &tls.Config{InsecureSkipVerify: false}

var app = tview.NewApplication()

var pages = tview.NewPages()

func upgradeToTLS(conn *ldap.Conn, tlsConfig *tls.Config) (*ldap.Conn, error) {
    if conn == nil {
        return nil, fmt.Errorf("Current connection is invalid")
    }

	err := conn.StartTLS(tlsConfig)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func connectLDAP(ldapServer string, ldapPort int, ldapUsername string, ldapPassword string) (*ldap.Conn, error) {
    var conn *ldap.Conn
    var err error

    if ldaps {
        tlsConfig := secureTlsConfig
        if insecure {
            tlsConfig = insecureTlsConfig
        }

        conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort), tlsConfig)
    } else {
        conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
    }

    if err != nil {
        updateLog(fmt.Sprint(err), "red")
        return nil, err
    }

    err = conn.Bind(ldapUsername, ldapPassword)
    if err != nil {
        updateLog(fmt.Sprint(err), "red")
        return nil, err
    }

    updateLog("Connection success", "green")
    return conn, nil
}

func queryLDAP(conn *ldap.Conn, baseDN string, searchFilter string, scope int) ([]*ldap.Entry, error) {
    searchRequest := ldap.NewSearchRequest(
        baseDN,
        scope, ldap.NeverDerefAliases, 0, 0, false,
        searchFilter,
        []string{},
        nil,
    )

    sr, err := conn.Search(searchRequest)
    if err != nil {
        updateLog(fmt.Sprint(err), "red")
        return nil, err
    }

    return sr.Entries, nil
}

func updateStateBox(target *tview.TextView, control bool) {
    if control {
        target.SetText("ON")
        target.SetTextColor(tcell.GetColor("green"))
    } else {
        target.SetText("OFF")
        target.SetTextColor(tcell.GetColor("red"))
    }
}

func updateLog(msg string, color string) {
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02 15:04:05")

    logPanel.SetText("[" + formattedTime + "] " + msg).SetTextColor(tcell.GetColor(color))
}

func appKeyHandler(event *tcell.EventKey) *tcell.EventKey {
    _, isTextArea := app.GetFocus().(*tview.TextArea)
    _, isInputField := app.GetFocus().(*tview.InputField)

    if isTextArea || isInputField {
        return event
    }

    if event.Key() == tcell.KeyCtrlJ {
        dstPage := (page+1) % pageCount
        pages.SwitchToPage(fmt.Sprintf("page-%d", dstPage))
        switch dstPage {
        case 0:
            app.SetFocus(treePanel)
        case 1:
            app.SetFocus(searchTreePanel)
        case 2:
            app.SetFocus(groupMembersPanel)
        case 3:
            app.SetFocus(daclEntriesPanel)
        }
        page = dstPage

        return nil
    }

    if event.Key() == tcell.KeyEscape || event.Rune() == 'q' {
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
    case 'r', 'R':
        if conn != nil {
            conn.Close()
        }
        conn, err = connectLDAP(ldapServer, ldapPort, ldapUsername, ldapPassword)
        updateStateBox(tlsPanel, ldaps)
        updateStateBox(statusPanel, err == nil)
    case 'h', 'H':
        showHeader = !showHeader
        if showHeader {
            appPanel.RemoveItem(headerPanel)
        } else {
            appPanel.RemoveItem(pages)
            appPanel.AddItem(headerPanel, 0, 1, false)
            appPanel.AddItem(pages, 0, 8, false)
        }
    case 'l', 'L':
        credsForm := tview.NewForm()

        credsForm = credsForm.
            AddInputField("Server", ldapServer, 20, nil, nil).
            AddInputField("Port", strconv.Itoa(ldapPort), 20, nil, nil).
            AddInputField("Username", ldapUsername, 20, nil, nil).
            AddPasswordField("Password", ldapPassword, 20, '*', nil).
            SetFieldBackgroundColor(tcell.GetColor("black")).
            AddButton("Save", func() {
                ldapServer = credsForm.GetFormItemByLabel("Server").(*tview.InputField).GetText()
                ldapPort, _ = strconv.Atoi(credsForm.GetFormItemByLabel("Port").(*tview.InputField).GetText())
                ldapUsername = credsForm.GetFormItemByLabel("Username").(*tview.InputField).GetText()
                ldapPassword = credsForm.GetFormItemByLabel("Password").(*tview.InputField).GetText()
                app.SetRoot(appPanel, false).SetFocus(treePanel)
            }).
            AddButton("Cancel", func() {
                app.SetRoot(appPanel, false).SetFocus(treePanel)
            })

        credsForm.SetTitle("Connection Config").SetBorder(true)
        app.SetRoot(credsForm, true).SetFocus(credsForm)
    case 'u', 'U':
        tlsConfig := secureTlsConfig
        if insecure {
            tlsConfig = insecureTlsConfig
        }

        conn, err = upgradeToTLS(conn, tlsConfig)
        if err != nil {
            updateLog(fmt.Sprint(err), "red")
        } else {
            updateLog("StartTLS request successful", "green")
            updateStateBox(tlsPanel, true)
        }

        updateStateBox(statusPanel, err == nil)
    }

    return event
}


func main() {
    flag.StringVar(&ldapServer, "server", "", "LDAP server address")
    flag.IntVar(&ldapPort, "port", 389, "LDAP server port")
    flag.StringVar(&ldapUsername, "username", "", "LDAP username")
    flag.StringVar(&ldapPassword, "password", "", "LDAP password")
    flag.StringVar(&rootDN, "rootDN", "", "Initial root DN")
    flag.StringVar(&searchFilter, "searchFilter", "(objectClass=*)", "Initial LDAP search filter")
    flag.BoolVar(&emojis, "emojis", true, "Prefix objects with emojis")
    flag.BoolVar(&colors, "colors", true, "Colorize objects")
    flag.BoolVar(&expandAttrs, "expandAttrs", true, "Expand multi-value attributes")
    flag.IntVar(&attrLimit, "attrLimit", 20, "Number of attribute values to render for multi-value attributes when expandAttrs is set true")
    flag.BoolVar(&formatAttrs, "formatAttrs", true, "Format attributes into human-readable values")
    flag.BoolVar(&cacheEntries, "cacheEntries", false, "Keep loaded entries in memory while the program is open and don't query them again")
    flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification for LDAPS/StartTLS")
    flag.BoolVar(&ldaps, "ldaps", false, "Use LDAPS for initial connection")
    /*
    flag.Synonym("s", "server")
    flag.Synonym("p", "port")
    flag.Synonym("U", "username")
    flag.Synonym("P", "password")
    flag.Synonym("dn", "rootDN")
    flag.Synonym("f", "searchFilter")
    flag.Synonym("e", "emojis")
    flag.Synonym("c", "colors")
    flag.Synonym("ce", "cacheEntries")
    flag.Synonym("ea", "expandAttrs")
    flag.Synonym("fa", "formatAttrs")
    */

    flag.Parse()

    logPanel = tview.NewTextView()
    logPanel.SetTitle("Last Log")
    logPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    if ldapServer == "" || ldapUsername == "" || ldapPassword == "" {
        fmt.Println("Error: server, username, and password are required.")
        flag.Usage()
        os.Exit(1)
    }

    conn, err = connectLDAP(ldapServer, ldapPort, ldapUsername, ldapPassword)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    if rootDN == "" {
        rootDN, err = utils.FindRootDN(conn)
        if err != nil {
            log.Fatal(err)
        }
    }

    tlsPanel = tview.NewTextView()
    tlsPanel.SetTitle("TLS")
    tlsPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    statusPanel = tview.NewTextView()
    statusPanel.SetTitle("Connection")
    statusPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    formatFlagPanel = tview.NewTextView()
    formatFlagPanel.SetTitle("Formatting")
    formatFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    emojiFlagPanel = tview.NewTextView()
    emojiFlagPanel.SetTitle("Emoji")
    emojiFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    colorFlagPanel = tview.NewTextView()
    colorFlagPanel.SetTitle("Colors")
    colorFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    expandFlagPanel = tview.NewTextView()
    expandFlagPanel.SetTitle("ExpandAttrs")
    expandFlagPanel.SetTextAlign(tview.AlignCenter).SetBorder(true)

    // Pages setup
    InitExplorerPage()
    InitSearchPage()
    InitGroupPage()
    InitDaclPage()

    pages.AddPage("page-0", explorerPage, true, true)

    pages.AddPage("page-1", searchPage, true, false)

    pages.AddPage("page-2", groupPage, true, false)

    pages.AddPage("page-3", daclPage, true, false)

    headerPanel = tview.NewFlex().
        AddItem(tlsPanel, 0, 1, false).
        AddItem(statusPanel, 0, 1, false).
        AddItem(formatFlagPanel, 0, 1, false).
        AddItem(colorFlagPanel, 0, 1, false).
        AddItem(expandFlagPanel, 0, 1, false).
        AddItem(emojiFlagPanel, 0, 1, false)

    appPanel = tview.NewFlex().SetDirection(tview.FlexRow).
        AddItem(logPanel, 0, 1, false).
        AddItem(headerPanel, 0, 1, false).
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
