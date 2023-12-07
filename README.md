# godap

![](https://img.shields.io/github/go-mod/go-version/Macmod/godap) ![](https://img.shields.io/github/languages/code-size/Macmod/godap) ![](https://img.shields.io/github/license/Macmod/godap) ![](https://img.shields.io/github/actions/workflow/status/Macmod/godap/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Macmod/godap)](https://goreportcard.com/report/github.com/Macmod/godap)

`godap` is a complete TUI for LDAP written in Golang.

# Features

* Formats date/time, boolean and other categorical attributes into readable text
* Supports changing the search filter & base DN for the query
* LDAPS & StartTLS support
* Pretty colors & cool emojis
* Quick explorer that loads objects on demand
* Recursive object search bundled with useful saved searches
* Group members & user groups lookup
* Supports basic attribute editing
* Basic DACL viewer

# Installation

```bash
go install github.com/Macmod/godap@latest
```

# Usage

```bash
$ godap -username <username>@<domain> -password <password> -server <hostname or IP>
```

## Optional flags

* `-rootDN <distinguishedName>` - Initial root DN (default: automatic)
* `-searchFilter <search filter>` - Initial LDAP search filter (default: `(objectClass=*)`)
* `-emojis` - Prefix objects with emojis (default: `true`, to change use `-emojis=false`)
* `-colors` - Colorize objects (default: `true`, to change use `-colors=false`)
* `-expandAttrs` - Expand multi-value attributes (default: `true`, to change use `-expandAttrs=false`)
* `-attrLimit` - Number of attribute values to render for multi-value attributes when `expandAttrs` is `true` (default: `20`)
* `-formatAttrs` - Format attributes into human-readable values (default: `true`, to change use `-formatAttrs=false`)
* `-cacheEntries` - Keep loaded entries in memory while the program is open and don't query them again (default: `false`)
* `-insecure` - Skip TLS verification for LDAPS/StartTLS (default: `false`)
* `-ldaps` - Use LDAPS for initial connection (default: `false`)

## Keybindings

* Ctrl + `J` - Next panel
* `f` / `F` - Toggle attribute formatting
* `e` / `E` - Toggle emojis
* `c` / `C` - Toggle colors
* `a` / `A` - Toggle attribute expansion for multi-value attributes
* `l / L` - Change current server address & credentials
* `r / R` - Reconnect to the server
* `u / U` - Upgrade connection to use TLS (with StartTLS)
* Ctrl + `e / E` - Edit the selected attribute of the selected object
* Ctrl + `n / N` - Create a new attribute in the selected object
* Ctrl + `p / P` - Change the password of the selected user
* `Delete` - Deletes the selected object or attribute (after prompting for confirmation)
* `q` - Exit the program
* `h` - Show/hide headers

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
