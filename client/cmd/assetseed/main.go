// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/client/core"
)

func main() {
	var appSeed string
	flag.StringVar(&appSeed, "seed", "", "Bison Wallet application seed (128 hexadecimal characters)")
	var assetID uint
	flag.UintVar(&assetID, "asset", 0, "Asset ID. BIP-0044 coin type (integer).\n"+
		"See https://github.com/satoshilabs/slips/blob/master/slip-0044.md")
	flag.Parse()

	if appSeed == "" {
		flag.Usage()
		os.Exit(1)
	}

	appSeedB, err := hex.DecodeString(appSeed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad app seed: %v\n", err)
		os.Exit(1)
	}

	if len(appSeedB) != 64 {
		fmt.Fprintf(os.Stderr, "app seed is %d bytes, expected 64\n", len(appSeedB))
		os.Exit(1)
	}

	if tkn := asset.TokenInfo(uint32(assetID)); tkn != nil {
		fmt.Fprintf(os.Stderr, "this is a token. did you want asset ID %d for %s?\n", tkn.ParentID, asset.Asset(tkn.ParentID).Info.Name)
		os.Exit(1)
	}

	seed, _ := core.AssetSeedAndPass(uint32(assetID), appSeedB)
	fmt.Printf("%x\n", seed)

	os.Exit(0)
}
