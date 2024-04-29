module github.com/Macmod/godap/v2

go 1.21.4

require (
	github.com/gdamore/tcell/v2 v2.7.1
	github.com/go-asn1-ber/asn1-ber v1.5.5
	github.com/go-ldap/ldap v0.0.0-20240314174501-83a306c8f13f
	github.com/go-ldap/ldap/v3 v3.4.7-0.20240314174501-83a306c8f13f
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/rivo/tview v0.0.0-20240413115534-b0d41c484b95
	github.com/spf13/cobra v1.8.0
	golang.org/x/text v0.14.0
	h12.io/socks v1.0.3
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/term v0.18.0 // indirect
)

replace github.com/jcmturner/gokrb5/v8 => github.com/Macmod/gokrb5/v8 v8.4.5-0.20240428143821-ea9a660f0f44

replace github.com/go-ldap/ldap/v3 => github.com/Macmod/ldap/v3 v3.0.0-20240415020653-119bc6d73ac6
