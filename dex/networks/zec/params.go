// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org

package zec

import (
	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/networks/btc"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	// MinimumTxOverhead
	// 4 header + 4 nVersionGroup + 1 varint input count + 1 varint output count
	// + 4 lockTime + 4 nExpiryHeight + 8 valueBalanceSapling + 1 varint nSpendsSapling
	// + 1 varint nOutputsSapling + 1 varint nJoinSplit
	MinimumTxOverhead = 29

	InitTxSizeBase = MinimumTxOverhead + btc.P2PKHOutputSize + btc.P2SHOutputSize // 29 + 34 + 32 = 95
	InitTxSize     = InitTxSizeBase + btc.RedeemP2PKHInputSize                    // 95 + 149 = 244

	// LegacyFeeRate returns a standard 10 zats / byte. Prior to ZIP-0317, Zcash
	// used a standard tx fee of 1000 zats, regardless of tx size. However,
	// zcashd v5.5 begins making stricter fee requirements for both relay and
	// block inclusion. The release notes state that relay by default still
	// works with 1000 zat fee txns, but it may be adjusted by operators, and it
	// may need to be set to the higher ZIP 317 rate. For mining, there is a
	// small allowance on the number of "unpaid actions" allowed in a block, so
	// we should take care to pay the ZIP 317 "conventional" rate, which is
	// multiples of 5000 zats, and a minimum of 10000. To ensure we have no
	// unpaid actions in our (transparent) transactions, we need a higher rate.
	// For a 242 byte transaction, like a swap init, we can emulate this with
	// about 42 zats/byte. Even with 100 zats/byte, our typical redeem of ~342
	// bytes would pay 34200 zats, which is only about a penny, so to ensure our
	// transactions are relayed and mined, we go with a high rate.
	LegacyFeeRate = 84
)

var (
	UnitInfo = dex.UnitInfo{
		AtomicUnit: "zats",
		Conventional: dex.Denomination{
			Unit:             "ZEC",
			ConversionFactor: 1e8,
		},
		Alternatives: []dex.Denomination{
			{
				Unit:             "mZEC",
				ConversionFactor: 1e5,
			},
			{
				Unit:             "µZEC",
				ConversionFactor: 1e2,
			},
		},
		FeeRateDenom: "action",
	}

	// MainNetParams are the clone parameters for mainnet. Zcash,
	// like Decred, uses two bytes for their address IDs. We will convert
	// between address types on the fly and use these spoof parameters
	// internally.
	MainNetParams = btc.ReadCloneParams(&btc.CloneParams{
		Name:             "mainnet",
		ScriptHashAddrID: 0xBD,
		PubKeyHashAddrID: 0xB8,
		CoinbaseMaturity: 100,
		Net:              0x24e92764,
	})
	// TestNet4Params are the clone parameters for testnet.
	TestNet4Params = btc.ReadCloneParams(&btc.CloneParams{
		Name:             "testnet4",
		PubKeyHashAddrID: 0x25,
		ScriptHashAddrID: 0xBA,
		CoinbaseMaturity: 100,
		Net:              0xfa1af9bf,
	})
	// RegressionNetParams are the clone parameters for simnet.
	RegressionNetParams = btc.ReadCloneParams(&btc.CloneParams{
		Name:             "regtest",
		PubKeyHashAddrID: 0x25,
		ScriptHashAddrID: 0xBA,
		CoinbaseMaturity: 100,
		Net:              0xaae83f5f,
	})

	// MainNetAddressParams are used for string address parsing. We use a
	// spoofed address internally, since Zcash uses a two-byte address ID
	// instead of a 1-byte ID.
	MainNetAddressParams = &AddressParams{
		ScriptHashAddrID: [2]byte{0x1C, 0xBD},
		PubKeyHashAddrID: [2]byte{0x1C, 0xB8},
	}

	// TestNet4AddressParams are used for string address parsing.
	TestNet4AddressParams = &AddressParams{
		ScriptHashAddrID: [2]byte{0x1C, 0xBA},
		PubKeyHashAddrID: [2]byte{0x1D, 0x25},
	}

	// RegressionNetAddressParams are used for string address parsing.
	RegressionNetAddressParams = &AddressParams{
		ScriptHashAddrID: [2]byte{0x1C, 0xBA},
		PubKeyHashAddrID: [2]byte{0x1D, 0x25},
	}
)

func init() {
	for _, params := range []*chaincfg.Params{MainNetParams, TestNet4Params, RegressionNetParams} {
		err := chaincfg.Register(params)
		if err != nil {
			panic("failed to register zec parameters: " + err.Error())
		}
	}
}
