package wasmcore

import (
	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/client/core"
	"decred.org/dcrdex/dex/encode"
)

// xcWallet is a wallet. Use (*Core).loadWallet to construct a xcWallet.
type XcWallet struct {
	asset.Wallet
	AssetID           uint32
	Symbol            string
	supportedVersions []uint32
	walletType        string
	encPass           []byte // empty means wallet not password protected
	balance           *core.WalletBalance
	pw                encode.PassBytes
	address           string
	monitored         uint32 // startWalletSyncMonitor goroutines monitoring sync status
	hookedUp          bool
	syncStatus        *asset.SyncStatus
	disabled          bool
}
