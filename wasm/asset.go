package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/dex/config"
	"decred.org/dcrwallet/v4/wallet"
	"decred.org/dcrwallet/v4/wallet/udb"
	"github.com/decred/dcrd/chaincfg/v3"
)

type Kind int

// Error kinds.
const (
	Other               Kind = iota // Unclassified error -- does not appear in error strings
	Bug                             // Error is known to be a result of our bug
	Invalid                         // Invalid operation
	Permission                      // Permission denied
	IO                              // I/O error
	Exist                           // Item already exists
	NotExist                        // Item does not exist
	Encoding                        // Invalid encoding
	Crypto                          // Encryption or decryption error
	Locked                          // Wallet is locked
	Passphrase                      // Invalid passphrase
	Seed                            // Invalid seed
	WatchingOnly                    // Missing private keys
	InsufficientBalance             // Insufficient balance to create transaction (perhaps due to UTXO selection requirements)
	ScriptFailure                   // Transaction scripts do not execute (usually due to missing sigs)
	Policy                          // Transaction rejected by wallet policy
	Consensus                       // Consensus violation
	DoubleSpend                     // Transaction is a double spend
	Protocol                        // Protocol violation
	NoPeers                         // Decred network is unreachable due to lack of peers or dcrd RPC connections
	Deployment                      // Inactive consensus deployment
)

type RecoveryCfg struct {
	NumExternalAddresses uint32 `ini:"numexternaladdr"`
	NumInternalAddresses uint32 `ini:"numinternaladdr"`
	GapLimit             uint32 `ini:"gaplimit"`
}

const (
	walletDbName           = "wallet.db"
	dbDriver               = "bdb"
	defaultAllowHighFees   = false
	defaultRelayFeePerKb   = 1e4
	defaultAccountGapLimit = 3
	defaultManualTickets   = false
	defaultMixSplitLimit   = 10
	defaultAcct            = 0
	mixedAccountName       = "mixed"
	tradingAccountName     = "dextrading"
)

func CreateWasmWallet(params *asset.CreateWalletParams) error {
	if params.Type != walletTypeSPV {
		return fmt.Errorf("SPV is the only seeded wallet type. required = %q, requested = %q", walletTypeSPV, params.Type)
	}
	if len(params.Seed) == 0 {
		return errors.New("wallet seed cannot be empty")
	}
	if len(params.DataDir) == 0 {
		return errors.New("must specify wallet data directory")
	}
	chainParams, err := parseChainParams(params.Net)
	if err != nil {
		return fmt.Errorf("error parsing chain params: %w", err)
	}

	recoveryCfg := new(RecoveryCfg)
	err = config.Unmapify(params.Settings, recoveryCfg)
	if err != nil {
		return err
	}

	return createWasmSPVWallet(params.Pass, params.Seed, params.DataDir, recoveryCfg.NumExternalAddresses,
		recoveryCfg.NumInternalAddresses, recoveryCfg.GapLimit, chainParams)
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func createWasmSPVWallet(pw, seed []byte, dataDir string, extIdx, intIdx, gapLimit uint32, chainParams *chaincfg.Params) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	dbPath := filepath.Join(dataDir, walletDbName)
	exists, err := fileExists(dbPath)
	if err != nil {
		return fmt.Errorf("error checking file existence for %q: %w", dbPath, err)
	}
	if exists {
		return fmt.Errorf("database file already exists at %q", dbPath)
	}
	// Create the wallet database backed by bolt db.
	db, err := wallet.CreateDB(dbDriver, dbPath)
	if err != nil {
		return fmt.Errorf("CreateDB error: %w", err)
	}

	// Initialize the newly created database for the wallet before opening.
	err = wallet.Create(ctx, db, nil, pw, seed, chainParams)
	if err != nil {
		return fmt.Errorf("wallet.Create error: %w", err)
	}

	// Open the newly-created wallet.
	w, err := wallet.Open(ctx, newWalletConfig(db, chainParams, gapLimit))
	if err != nil {
		return fmt.Errorf("wallet.Open error: %w", err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			fmt.Println("Error closing database:", err)
		}
	}()

	err = w.UpgradeToSLIP0044CoinType(ctx)
	if err != nil {
		return err
	}

	err = w.Unlock(ctx, pw, nil)
	if err != nil {
		return fmt.Errorf("error unlocking wallet: %w", err)
	}

	err = w.SetAccountPassphrase(ctx, defaultAcct, pw)
	if err != nil {
		return fmt.Errorf("error setting Decred account %d passphrase: %v", defaultAcct, err)
	}

	err = setupMixingAccounts(ctx, w, pw)
	if err != nil {
		return fmt.Errorf("error setting up mixing accounts: %v", err)
	}

	w.Lock()

	if extIdx > 0 || intIdx > 0 {
		err = extendAddresses(ctx, extIdx, intIdx, w)
		if err != nil {
			return fmt.Errorf("failed to set starting address indexes: %w", err)
		}
	}

	return nil
}

func extendAddresses(ctx context.Context, extIdx, intIdx uint32, dcrw *wallet.Wallet) error {
	if err := dcrw.SyncLastReturnedAddress(ctx, defaultAcct, udb.ExternalBranch, extIdx); err != nil {
		return fmt.Errorf("error syncing external branch index: %w", err)
	}

	if err := dcrw.SyncLastReturnedAddress(ctx, defaultAcct, udb.InternalBranch, intIdx); err != nil {
		return fmt.Errorf("error syncing internal branch index: %w", err)
	}

	return nil
}

func setupMixingAccounts(ctx context.Context, w *wallet.Wallet, pw []byte) error {
	requiredAccts := []string{mixedAccountName, tradingAccountName} // unmixed (default) acct already exists
	for _, acct := range requiredAccts {
		_, err := w.AccountNumber(ctx, acct)
		if err == nil {
			continue // account exist, check next account
		}

		acctNum, err := w.NextAccount(ctx, acct)
		if err != nil {
			return err
		}
		if err = w.SetAccountPassphrase(ctx, acctNum, pw); err != nil {
			return err
		}
	}

	return nil
}

func newWalletConfig(db wallet.DB, chainParams *chaincfg.Params, gapLimit uint32) *wallet.Config {
	if gapLimit < wallet.DefaultGapLimit {
		gapLimit = wallet.DefaultGapLimit
	}
	return &wallet.Config{
		DB:              db,
		GapLimit:        gapLimit,
		AccountGapLimit: defaultAccountGapLimit,
		ManualTickets:   defaultManualTickets,
		AllowHighFees:   defaultAllowHighFees,
		RelayFee:        defaultRelayFeePerKb,
		Params:          chainParams,
		MixSplitLimit:   defaultMixSplitLimit,
	}
}
