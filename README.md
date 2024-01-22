# godap

![](https://img.shields.io/github/go-mod/go-version/Macmod/godap) ![](https://img.shields.io/github/languages/code-size/Macmod/godap) ![](https://img.shields.io/github/license/Macmod/godap) ![](https://img.shields.io/github/actions/workflow/status/Macmod/godap/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Macmod/godap)](https://goreportcard.com/report/github.com/Macmod/godap)

`godap` is a complete TUI for LDAP written in Golang.

# Screenshots

![images/page1.png](images/page1.png)

![images/page2.png](images/page2.png)

![images/page3.png](images/page3.png)

![images/page4.png](images/page4.png)

# Features

* Formats date/time, boolean and other categorical attributes into readable text
* Supports changing the search filter & base DN for the query
* LDAPS & StartTLS support
* Pretty colors & cool emojis
* Quick explorer that loads objects on demand
* Recursive object search bundled with useful saved searches
* Group members & user groups lookup
* Supports creation, editing and removal of objects and attributes
* Supports exporting specific subtrees of the directory into JSON files
* Basic DACL viewer

# Installation

```bash
go install github.com/Macmod/godap@latest
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

To use StartTLS to upgrade an existing connection to use TLS, use the `u` keybinding inside godap. Note that you must have started godap with `-I` to use the upgrade command properly if the server certificate is not trusted by your client.

## Flags

* `-u`,`--username` - Username for bind
* `-p`,`--password` - Password for bind
* `-P`,`--port` - Custom port for the connection (default: `389`)
* `-r`,`--rootDN <distinguishedName>` - Initial root DN (default: automatic)
* `-f`,`--filter <search filter>` - Initial LDAP search filter (default: `(objectClass=*)`)
* `-E`,`--emojis` - Prefix objects with emojis (default: `true`, to change use `-emojis=false`)
* `-C`,`--colors` - Colorize objects (default: `true`, to change use `-colors=false`)
* `-A`,`--expand` - Expand multi-value attributes (default: `true`, to change use `-expand=false`)
* `-L`,`--limit` - Number of attribute values to render for multi-value attributes when `-expand` is `true` (default: `20`)
* `-F`,`--format` - Format attributes into human-readable values (default: `true`, to change use `-format=false`)
* `-M`,`--cache` - Keep loaded entries in memory while the program is open and don't query them again (default: `false`)
* `-I`,`--insecure` - Skip TLS verification for LDAPS/StartTLS (default: `false`)
* `-S`,`--ldaps` - Use LDAPS for initial connection (default: `false`)
* `-G`,`--paging` - Default paging size for regular queries
* `-d`,`--domain` - Domain for NTLM bind
* `-H`,`--hashes` - Hashes for NTLM bind

## Keybindings

| Keybinding                        | Context                                                     | Action                                                   |
| --------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------- |
| `Ctrl` + `J`                      | Global                                                      | Next panel                                                   |
| `f` / `F`                         | Global                                                      | Toggle attribute formatting                                  |
| `e` / `E`                         | Global                                                      | Toggle emojis                                                |
| `c` / `C`                         | Global                                                      | Toggle colors                                                |
| `a` / `A`                         | Global                                                      | Toggle attribute expansion for multi-value attributes        |
| `l` / `L`                           | Global                                                      | Change current server address & credentials                  |
| `r` / `R`                           | Global                                                      | Reconnect to the server                                       |
| `u` / `U`                           | Global                                                      | Upgrade connection to use TLS (with StartTLS)                |
| `Ctrl` + `e / E`                  | Attributes panel                                             | Edit the selected attribute of the selected object           |
| `Ctrl` + `n / N` | Attributes panel                                             | Create a new attribute in the selected object                |
| `Ctrl` + `n / N` | Explorer panel                                              | Create a new object under the selected object                 |
| `Ctrl` + `s / S`  | Explorer panel                                              | Export all loaded nodes in the selected subtree into a JSON file   |
| `Ctrl` + `p / P`                  | Explorer panel                              | Change the password of the selected user or computer account  |
| `Delete`                          | Explorer/attributes panel        | Deletes the selected object or attribute                      |
| `h` / `H`                               | Global                                                      | Show/hide headers                                             |
| `q`                               | Global                                                      | Exit the program                                              |

# Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/godap/issues/new) or by [submitting a pull request](https://github.com/Macmod/godap/pulls).

# Acknowledgements

DACL parsing code was taken from these tools:

* [ldapper](https://github.com/Synzack/ldapper)
* [Darksteel](https://github.com/wjlab/Darksteel)

# License

The MIT License (MIT)

Copyright (c) 2023 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
