# godap

![GitHub Release](https://img.shields.io/github/v/release/Macmod/godap) ![](https://img.shields.io/github/go-mod/go-version/Macmod/godap) ![](https://img.shields.io/github/languages/code-size/Macmod/godap) ![](https://img.shields.io/github/license/Macmod/godap) ![](https://img.shields.io/github/actions/workflow/status/Macmod/godap/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Macmod/godap)](https://goreportcard.com/report/github.com/Macmod/godap) ![GitHub Downloads](https://img.shields.io/github/downloads/Macmod/godap/total)

<h3>A complete TUI for LDAP.</h3>

![Demo](images/godap.gif)

# Summary

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
   * [Flags](#flags)
   * [Keybindings](#keybindings)
* [Tree Colors](#tree-colors)
* [Contributing](#contributing)
* [Acknowledgements](#acknowledgements)
* [Disclaimers](#disclaimers)

# Features

* 🗒️ Formats date/time, boolean and other categorical attributes into readable text
* 😎 Pretty colors & cool emojis
* 🔐 LDAPS & StartTLS support
* ⏩ Fast explorer that loads objects on demand
* 🔎 Recursive object search bundled with useful saved searches
* 👥 Group members & user groups lookup
* 🎡 Supports creation, editing and removal of objects and attributes
* 🚙 Supports moving and renaming objects
* 🗑️ Supports searching deleted & recycled objects
* 📁 Supports exporting specific subtrees of the directory into JSON files
* 🕹️ Interactive userAccountControl editor
* 🔥 Interactive DACL editor
* 🧦 SOCKS support

# Installation

```bash
go install github.com/Macmod/godap/v2@latest
```

# Usage

**Bind with username and password**

```bash
$ godap <hostname or IP> -u <username>@<domain> -p <password>
```

**Bind with an NTLM hash**

```bash
$ godap <hostname or IP> -u <username> -H <hash> [-d <domain>]
```

**Anonymous Bind**

```bash
$ godap <hostname or IP> -p anything
```

**LDAPS/StartTLS**

To use LDAPS for the initial connection (ignoring certificate validation) run:

```bash
$ godap <hostname or IP> [bind flags] -S -I -P 636
```

To use StartTLS to upgrade an existing connection to use TLS, use the `Ctrl + u` keybinding inside godap.

Notice that, if the server certificate is not trusted by your client, you must either have started godap with `-I` to use the upgrade command properly or toggle the `IgnoreCert` checkbox using the `l` keybinding before upgrading.

If LDAPS is available, you can also change the port using `l`, toggle the LDAPS checkbox, set the desired value for `IgnoreCert`, and reconnect with `Ctrl + r`.

**SOCKS**

To connect to LDAP through a SOCKS proxy include the flag `-x schema://ip:port`, where `schema` is one of `socks4`, `socks4a` or `socks5`.

You can also change the address of your proxy using the `l` keybinding.

## Flags

* `-u`,`--username` - Username for bind
* `-p`,`--password` - Password for bind
* `--passfile` - Path to a file containing the password for bind
* `-P`,`--port` - Custom port for the connection (default: `389`)
* `-r`,`--rootDN <distinguishedName>` - Initial root DN (default: automatic)
* `-f`,`--filter <search filter>` - Initial LDAP search filter (default: `(objectClass=*)`)
* `-E`,`--emojis` - Prefix objects with emojis (default: `true`, to change use `-emojis=false`)
* `-C`,`--colors` - Colorize objects (default: `true`, to change use `-colors=false`)
* `-A`,`--expand` - Expand multi-value attributes (default: `true`, to change use `-expand=false`)
* `-L`,`--limit` - Number of attribute values to render for multi-value attributes when `-expand` is `true` (default: `20`)
* `-F`,`--format` - Format attributes into human-readable values (default: `true`, to change use `-format=false`)
* `-M`,`--cache` - Keep loaded entries in memory while the program is open and don't query them again (default: `true`)
* `-D`,`--deleted` - Include deleted objects in all queries performed (default: `false`)
* `-T`,`--timeout` - Timeout for LDAP connections in seconds (default: `10`)
* `-I`,`--insecure` - Skip TLS verification for LDAPS/StartTLS (default: `false`)
* `-S`,`--ldaps` - Use LDAPS for initial connection (default: `false`)
* `-G`,`--paging` - Paging size for regular queries (default: `800`)
* `-d`,`--domain` - Domain for NTLM bind
* `-H`,`--hashes` - Hashes for NTLM bind
* `--hashfile` - Path to a file containing the hashes for NTLM bind
* `-x`,`--socks` - URI of SOCKS proxy to use for connection (supports `socks4://`, `socks4a://` or `socks5://` schemas)
* `-k`,`--schema` - Load GUIDs from schema on initialization (default: `false`)

## Keybindings

| Keybinding                        | Context                                                           | Action                                                                          |
| --------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| <kbd>Ctrl</kbd> + <kbd>Enter</kbd> (or <kbd>Ctrl</kbd> + <kbd>J</kbd>) | Global                                         | Next panel                                                    |
| <kbd>f</kbd> / <kbd>F</kbd>                         | Global                                                            | Toggle attribute formatting                                   |
| <kbd>e</kbd> / <kbd>E</kbd>                         | Global                                                            | Toggle emojis                                                 |
| <kbd>c</kbd> / <kbd>C</kbd>                         | Global                                                            | Toggle colors                                                 |
| <kbd>a</kbd> / <kbd>A</kbd>                         | Global                                                            | Toggle attribute expansion for multi-value attributes         |
| <kbd>d</kbd> / <kbd>D</kbd>                         | Global                                                            | Toggle "include deleted objects" flag                         |
| <kbd>l</kbd> / <kbd>L</kbd>                         | Global                                                            | Change current server address & credentials                   |
| <kbd>Ctrl</kbd> + <kbd>r</kbd>                  | Global                                                            | Reconnect to the server                                       |
| <kbd>Ctrl</kbd> + <kbd>u</kbd>                  | Global                                                            | Upgrade connection to use TLS (with StartTLS)                 |
| <kbd>Ctrl</kbd> + <kbd>f</kbd>                  | LDAP Explorer & Object Search pages                               | Open the finder to search for cached objects & attributes with regex                   |
| Right Arrow                                         | Explorer panel                                                    | Expand the children of the selected object                            |
| Left Arrow                                          | Explorer panel                                                    | Collapse the children of the selected object                          |
| <kbd>r</kbd> / <kbd>R</kbd>                         | Explorer panel                                                    | Reload the attributes and children of the selected object     |
| <kbd>Ctrl</kbd> + <kbd>n</kbd>                      | Explorer panel                                                    | Create a new object under the selected object                 |
| <kbd>Ctrl</kbd> + <kbd>s</kbd>                      | Explorer panel                                                    | Export all loaded nodes in the selected subtree into a JSON file |
| <kbd>Ctrl</kbd> + <kbd>p</kbd>                      | Explorer panel                                                    | Change the password of the selected user or computer account  |
| <kbd>Ctrl</kbd> + <kbd>a</kbd>                      | Explorer panel                                                    | Update the userAccountControl of the object interactively     |
| <kbd>Ctrl</kbd> + <kbd>l</kbd>                      | Explorer panel                                                    | Move the selected object to another location                  |
| <kbd>Delete</kbd>                                   | Explorer panel                                                    | Delete the selected object                                    |
| <kbd>r</kbd> / <kbd>R</kbd>                         | Attributes panel                                                  | Reload the attributes for the selected object                 |
| <kbd>Ctrl</kbd> + <kbd>e</kbd>                      | Attributes panel                                                  | Edit the selected attribute of the selected object            |
| <kbd>Ctrl</kbd> + <kbd>n</kbd>                      | Attributes panel                                                  | Create a new attribute in the selected object                 |
| <kbd>Delete</kbd>                                   | Attributes panel                                                  | Delete the selected attribute of the selected object          |
| <kbd>Ctrl</kbd> + <kbd>o</kbd>                      | DACL page                                                         | Change the owner of the current DACL                          |
| <kbd>Ctrl</kbd> + <kbd>k</kbd>                      | DACL page                                                         | Change the control flags of the current DACL                  |
| <kbd>Ctrl</kbd> + <kbd>n</kbd>                      | DACL entries panel                                                | Create a new ACE in the current DACL                          |
| <kbd>Ctrl</kbd> + <kbd>e</kbd>                      | DACL entries panel                                                | Edit the selected ACE of the current DACL                     |
| <kbd>Delete</kbd>                                   | DACL entries panel                                                | Deletes the selected ACE of the current DACL                  |
| <kbd>h</kbd> / <kbd>H</kbd>                         | Global                                                            | Show/hide headers                                             |
| <kbd>q</kbd>                                        | Global                                                            | Exit the program                                              |

## Tree Colors

The nodes in the explorer tree are colored as follows:

| Scenario                                | Color          |
| --------------------------------------- | -------------- |
| Object exists and is enabled            | Default        |
| Object exists and is disabled           | Yellow\*       |
| Object was deleted and not yet recycled | Gray\*         |
| Object was recycled already             | Red\*          |

\* Before v2.2.0, disabled nodes were colored red. This was the only custom color in the tree panel; other nodes were colored with default colors (the "include deleted objects" flag had not been implemented yet).

# Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/godap/issues/new) or by [submitting a pull request](https://github.com/Macmod/godap/pulls).

# Acknowledgements

* DACL parsing code and SOCKS code were adapted from the tools below:

  * [ldapper](https://github.com/Synzack/ldapper)
  * [Darksteel](https://github.com/wjlab/Darksteel)

* [BadBlood](https://github.com/davidprowe/BadBlood) was also very useful for testing during the development of the tool.

# Disclaimers

* Although some features might work with OpenLDAP (mainly in the explorer/search pages), the main focus of this tool is Active Directory.
* All features were tested and seem to be working properly on a Windows Server 2019, but this tool is highly experimental and I cannot test it extensively - I don't take responsibility for modifications that you execute and end up impacting your environment. If you observe any unexpected behaviors please [let me know](https://github.com/Macmod/godap/issues/new) so I can try to fix it.

# License

The MIT License (MIT)

Copyright (c) 2023 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
