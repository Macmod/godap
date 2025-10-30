module github.com/Macmod/godap/v2

go 1.24.0

toolchain go1.24.4

require (
	github.com/gdamore/tcell/v2 v2.9.0
	github.com/go-asn1-ber/asn1-ber v1.5.7
	github.com/go-ldap/ldap/v3 v3.4.12
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/rivo/tview v0.42.0
	github.com/spf13/cobra v1.10.1
	github.com/spf13/pflag v1.0.10
	golang.org/x/term v0.36.0
	golang.org/x/text v0.30.0
	h12.io/socks v1.0.3
	software.sslmate.com/src/go-pkcs12 v0.6.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.3.0 // indirect
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

replace github.com/jcmturner/gokrb5/v8 => github.com/Macmod/gokrb5/v8 v8.4.5-0.20240428143821-ea9a660f0f44

replace github.com/go-ldap/ldap/v3 => github.com/Macmod/ldap/v3 v3.0.0-20240415020653-119bc6d73ac6
