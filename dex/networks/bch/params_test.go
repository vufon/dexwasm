package bch

import (
	"encoding/hex"
	"testing"

	btctest "decred.org/dcrdex/dex/networks/btc/test"
)

func TestCompatibility(t *testing.T) {
	fromHex := func(str string) []byte {
		b, err := hex.DecodeString(str)
		if err != nil {
			t.Fatalf("error decoding %s: %v", str, err)
		}
		return b
	}

	// 2b381efec176b72da70e894a6dbba1fc1ba18a1d573af898e6f92915c0ca8209:1
	cashAddrP2PKH := "bitcoincash:qznf2drgsapgsejd95yp9nw0qzhw9mrcxsez7d78uv"
	p2pkhAddr, err := DecodeCashAddress(cashAddrP2PKH, MainNetParams)
	if err != nil {
		t.Fatalf("error p2pkh decoding CashAddr address: %v", err)
	}
	if !p2pkhAddr.IsForNet(MainNetParams) {
		t.Fatalf("IsForNet rejected address %v (%v) for net %v", p2pkhAddr, cashAddrP2PKH, MainNetParams.Name)
	}

	// b63e8090fe7140328d5d6ecdd6045b123e3f05742d9a749f2550fba7d0a6879f:1
	cashAddrP2SH := "bitcoincash:pqugctqhj096cufywe32rktfu5dpmnnrjgsznuudl2"
	p2shAddr, err := DecodeCashAddress(cashAddrP2SH, MainNetParams)
	if err != nil {
		t.Fatalf("error decoding p2sh CashAddr address: %v", err)
	}
	if !p2shAddr.IsForNet(MainNetParams) {
		t.Fatalf("IsForNet rejected address %v (%v) for net %v", p2shAddr, cashAddrP2SH, MainNetParams.Name)
	}

	// These scripts and addresses are just copy-pasted from random
	// getrawtransaction output.
	items := &btctest.CompatibilityItems{
		P2PKHScript: fromHex("76a914a6953468874288664d2d0812cdcf00aee2ec783488ac"),
		PKHAddr:     p2pkhAddr.String(),
		P2SHScript:  fromHex("a914388c2c1793cbac71247662a1d969e51a1dce639287"),
		SHAddr:      p2shAddr.String(),
	}
	btctest.CompatibilityCheck(t, items, MainNetParams)
}
