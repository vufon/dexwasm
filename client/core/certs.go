// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package core

import "decred.org/dcrdex/dex"

var dexDotDecredCert = []byte(`-----BEGIN CERTIFICATE-----
MIICeTCCAdqgAwIBAgIQZbivJ9Wrxpx0HHRV9tGn+TAKBggqhkjOPQQDBDA9MSIw
IAYDVQQKExlkY3JkZXggYXV0b2dlbmVyYXRlZCBjZXJ0MRcwFQYDVQQDEw5kZXgu
ZGVjcmVkLm9yZzAeFw0yMDA5MjcxODQwMDZaFw0zMDA5MjYxODQwMDZaMD0xIjAg
BgNVBAoTGWRjcmRleCBhdXRvZ2VuZXJhdGVkIGNlcnQxFzAVBgNVBAMTDmRleC5k
ZWNyZWQub3JnMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA3koCrZ4VR/Igiz6z
kOFfhAtfWDWuIot6DIJBdEuXMiPnFZqr8mFAiLP3+ihQNFEc3As7imE4fY5C2KUa
eMed+8IBqgVIlIq1SH99xhceua/UvzG1c+Av9Y2ZEwVgugYJu5d1mbBcomtHTp5n
ctCOOIpQN2KDtUzQqAZQSIrnimzedA+jeTB3MA4GA1UdDwEB/wQEAwICpDAPBgNV
HRMBAf8EBTADAQH/MFQGA1UdEQRNMEuCDmRleC5kZWNyZWQub3Jngglsb2NhbGhv
c3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGHEP6AAAAAAAAAAAAAAAAAAAGHBAoo
HjIwCgYIKoZIzj0EAwQDgYwAMIGIAkIBlXoes55DGvoOlAVxUW5Ju28Y4ts/ag9k
dDrsQSJuhzbhTcH0iTCq7Sg8bfGuAAP6U492kjqlZepBJUd4WCOyzg4CQgHDOOk5
pO281U39e0XpvQNkT6oJibnCmPVLXuD567Ibt2MfgZet47zGMiOLbQJkv4E8lMv3
wtXxBmKZLaFsxKCm7w==
-----END CERTIFICATE-----
`)

var simnetHarnessCert = []byte(`-----BEGIN CERTIFICATE-----
MIICpTCCAgagAwIBAgIQZMfxMkSi24xMr4CClCODrzAKBggqhkjOPQQDBDBJMSIw
IAYDVQQKExlkY3JkZXggYXV0b2dlbmVyYXRlZCBjZXJ0MSMwIQYDVQQDExp1YnVu
dHUtcy0xdmNwdS0yZ2ItbG9uMS0wMTAeFw0yMDA2MDgxMjM4MjNaFw0zMDA2MDcx
MjM4MjNaMEkxIjAgBgNVBAoTGWRjcmRleCBhdXRvZ2VuZXJhdGVkIGNlcnQxIzAh
BgNVBAMTGnVidW50dS1zLTF2Y3B1LTJnYi1sb24xLTAxMIGbMBAGByqGSM49AgEG
BSuBBAAjA4GGAAQApXJpVD7si8yxoITESq+xaXWtEpsCWU7X+8isRDj1cFfH53K6
/XNvn3G+Yq0L22Q8pMozGukA7KuCQAAL0xnuo10AecWBN0Zo2BLHvpwKkmAs71C+
5BITJksqFxvjwyMKbo3L/5x8S/JmAWrZoepBLfQ7HcoPqLAcg0XoIgJjOyFZgc+j
gYwwgYkwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8wZgYDVR0RBF8w
XYIadWJ1bnR1LXMtMXZjcHUtMmdiLWxvbjEtMDGCCWxvY2FsaG9zdIcEfwAAAYcQ
AAAAAAAAAAAAAAAAAAAAAYcEsj5QQYcEChAABYcQ/oAAAAAAAAAYPqf//vUPXDAK
BggqhkjOPQQDBAOBjAAwgYgCQgFMEhyTXnT8phDJAnzLbYRktg7rTAbTuQRDp1PE
jf6b2Df4DkSX7JPXvVi3NeBru+mnrOkHBUMqZd0m036aC4q/ZAJCASa+olu4Isx7
8JE3XB6kGr+s48eIFPtmq1D0gOvRr3yMHrhJe3XDNqvppcHihG0qNb0gyaiX18Cv
vF8Ti1x2vTkD
-----END CERTIFICATE-----
`)

var CertStore = map[dex.Network]map[string][]byte{
	dex.Mainnet: {
		"dex.decred.org:7232": dexDotDecredCert,
	},
	dex.Testnet: {
		"bison.exchange:17232": nil, // Uses certificate authority
	},
	dex.Simnet: {
		"127.0.0.1:17273": simnetHarnessCert,
	},
}
