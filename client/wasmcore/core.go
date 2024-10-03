package wasmcore

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/client/comms"
	"decred.org/dcrdex/client/core"
	"decred.org/dcrdex/client/db"
	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/encode"
	"decred.org/dcrdex/dex/encrypt"
	"decred.org/dcrdex/dex/order"
	"decred.org/dcrdex/dex/wait"
	"github.com/decred/dcrd/hdkeychain/v3"
)

var (
	unbip = dex.BipIDSymbol
)

type WasmCore struct {
	ctx           context.Context
	wg            sync.WaitGroup
	ready         chan struct{}
	rotate        chan struct{}
	cfg           *core.Config
	log           dex.Logger
	db            db.DB
	net           dex.Network
	lockTimeTaker time.Duration
	lockTimeMaker time.Duration
	intl          atomic.Value // *locale

	extensionModeConfig *core.ExtensionModeConfig

	// construction or init sets credentials
	credMtx     sync.RWMutex
	credentials *db.PrimaryCredentials

	loginMtx  sync.Mutex
	loggedIn  bool
	bondXPriv *hdkeychain.ExtendedKey // derived from creds.EncSeed on login

	seedGenerationTime uint64

	wsConstructor func(*comms.WsCfg) (comms.WsConn, error)
	newCrypter    func([]byte) encrypt.Crypter
	reCrypter     func([]byte, []byte) (encrypt.Crypter, error)
	latencyQ      *wait.TickerQueue

	connMtx sync.RWMutex

	walletMtx sync.RWMutex
	wallets   map[uint32]*XcWallet

	noteMtx   sync.RWMutex
	noteChans map[uint64]chan core.Notification

	sentCommitsMtx sync.Mutex
	sentCommits    map[order.Commitment]chan struct{}

	ratesMtx        sync.RWMutex
	fiatRateSources map[string]*commonRateSource

	reFiat chan struct{}

	pendingWalletsMtx sync.RWMutex
	pendingWallets    map[uint32]bool

	notes chan asset.WalletNotification

	pokesCache *pokesCache

	requestedActionMtx sync.RWMutex
	requestedActions   map[string]*asset.ActionRequiredNote
}

type rateFetcher func(context context.Context, logger dex.Logger, assets map[uint32]*core.SupportedAsset) map[uint32]float64

type fiatRateInfo struct {
	rate       float64
	lastUpdate time.Time
}

type pokesCache struct {
	sync.RWMutex
	cache         []*db.Notification
	cursor        int
	pokesCapacity int
}

type commonRateSource struct {
	fetchRates rateFetcher

	mtx       sync.RWMutex
	fiatRates map[uint32]*fiatRateInfo
}

// CreateWallet creates a new exchange wallet.
func (c *core.Core) CreateWallet(form *core.WalletForm) error {
	assetID := form.AssetID
	symbol := unbip(assetID)
	_, exists := c.wallet(assetID)
	if exists {
		return fmt.Errorf("%s wallet already exists", symbol)
	}
	// If this isn't a token, easy route.
	token := asset.TokenInfo(assetID)
	if token == nil {
		_, err = c.createWalletOrToken(crypter, walletPW, form)
		return err
	}

	// Prevent two different tokens from trying to create the parent simultaneously.
	if err = c.setWalletCreationPending(token.ParentID); err != nil {
		return err
	}
	defer c.setWalletCreationComplete(token.ParentID)

	// If the parent already exists, easy route.
	_, found := c.wallet(token.ParentID)
	if found {
		_, err = c.createWalletOrToken(crypter, walletPW, form)
		return err
	}

	// Double-registration mode. The parent wallet will be created
	// synchronously, then a goroutine is launched to wait for the parent to
	// sync before creating the token wallet. The caller can get information
	// about the asynchronous creation from WalletCreationNote notifications.

	// First check that they configured the parent asset.
	if form.ParentForm == nil {
		return fmt.Errorf("no parent wallet %d for token %d (%s), and no parent asset configuration provided",
			token.ParentID, assetID, unbip(assetID))
	}
	if form.ParentForm.AssetID != token.ParentID {
		return fmt.Errorf("parent form asset ID %d is not expected value %d",
			form.ParentForm.AssetID, token.ParentID)
	}

	// Create the parent synchronously.
	parentWallet, err := c.createWalletOrToken(crypter, walletPW, form.ParentForm)
	if err != nil {
		return fmt.Errorf("error creating parent wallet: %v", err)
	}

	if err = c.setWalletCreationPending(assetID); err != nil {
		return err
	}

	// Start a goroutine to wait until the parent wallet is synced, and then
	// begin creation of the token wallet.
	c.wg.Add(1)

	c.notify(newWalletCreationNote(TopicCreationQueued, "", "", db.Data, assetID))

	go func() {
		defer c.wg.Done()
		defer c.setWalletCreationComplete(assetID)
		defer crypter.Close()

		for {
			parentWallet.mtx.RLock()
			synced := parentWallet.syncStatus.Synced
			parentWallet.mtx.RUnlock()
			if synced {
				break
			}
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		// If there was a walletPW provided, it was for the parent wallet, so
		// use nil here.
		if _, err := c.createWalletOrToken(crypter, nil, form); err != nil {
			c.log.Errorf("failed to create token wallet: %v", err)
			subject, details := c.formatDetails(TopicQueuedCreationFailed, unbip(token.ParentID), symbol)
			c.notify(newWalletCreationNote(TopicQueuedCreationFailed, subject, details, db.ErrorLevel, assetID))
		} else {
			c.notify(newWalletCreationNote(TopicQueuedCreationSuccess, "", "", db.Data, assetID))
		}
	}()
	creationQueued = true
	return nil
}

func createOnWallet(form *core.WalletForm) (wallet *XcWallet, err error) {
	assetID := form.AssetID
	symbol := unbip(assetID)
	token := asset.TokenInfo(assetID)
	var dbWallet *db.Wallet
	dbWallet, err = createWallet(assetID, form)
	if err != nil {
		return nil, err
	}

	wallet, err = c.loadWallet(dbWallet)
	if err != nil {
		return nil, fmt.Errorf("error loading wallet for %d -> %s: %w", assetID, symbol, err)
	}
	// Block PeersChange until we know this wallet is ready.
	atomic.StoreUint32(wallet.broadcasting, 0)

	dbWallet.Address, err = c.connectWallet(wallet)
	if err != nil {
		return nil, err
	}

	if c.cfg.UnlockCoinsOnLogin {
		if err = wallet.ReturnCoins(nil); err != nil {
			c.log.Errorf("Failed to unlock all %s wallet coins: %v", unbip(wallet.AssetID), err)
		}
	}

	initErr := func(s string, a ...any) (*xcWallet, error) {
		_ = wallet.Lock(2 * time.Second) // just try, but don't confuse the user with an error
		wallet.Disconnect()
		return nil, fmt.Errorf(s, a...)
	}

	err = c.unlockWallet(crypter, wallet) // no-op if !wallet.Wallet.Locked() && len(encPW) == 0
	if err != nil {
		wallet.Disconnect()
		return nil, fmt.Errorf("%s wallet authentication error: %w", symbol, err)
	}

	balances, err := c.walletBalance(wallet)
	if err != nil {
		return initErr("error getting wallet balance for %s: %w", symbol, err)
	}
	wallet.setBalance(balances)         // update xcWallet's WalletBalance
	dbWallet.Balance = balances.Balance // store the db.Balance

	// Store the wallet in the database.
	err = c.db.UpdateWallet(dbWallet)
	if err != nil {
		return initErr("error storing wallet credentials: %w", err)
	}

	c.log.Infof("Created %s wallet. Balance available = %d / "+
		"locked = %d / locked in contracts = %d, Deposit address = %s",
		symbol, balances.Available, balances.Locked, balances.ContractLocked,
		dbWallet.Address)

	// The wallet has been successfully created. Store it.
	c.updateWallet(assetID, wallet)

	atomic.StoreUint32(wallet.broadcasting, 1)
	c.notify(newWalletStateNote(wallet.state()))
	c.walletCheckAndNotify(wallet)

	return wallet, nil
}

func createWallet(appSeed []byte, walletPW []byte, assetID uint32, form *core.WalletForm) (*db.Wallet, error) {
	walletDef, err := asset.WalletDef(assetID, form.Type)
	if err != nil {
		return nil, newError(assetSupportErr, "asset.WalletDef error: %w", err)
	}

	// Sometimes core will insert data into the Settings map to communicate
	// information back to the wallet, so it cannot be nil.
	if form.Config == nil {
		form.Config = make(map[string]string)
	}
	if walletDef.Seeded {
		walletPW, err = createSeededWallet(appSeed, assetID, form)
		if err != nil {
			return nil, err
		}
	}

	var encPW []byte
	if len(walletPW) > 0 {
		encPW, err = crypter.Encrypt(walletPW)
		if err != nil {
			return nil, fmt.Errorf("wallet password encryption error: %w", err)
		}
	}
	fmt.Println("check external after: ", hex.EncodeToString(walletPW))
	return &db.Wallet{
		Type:        walletDef.Type,
		AssetID:     assetID,
		Settings:    form.Config,
		EncryptedPW: encPW,
		// Balance and Address are set after connect.
	}, nil
}

func createSeededWallet(appSeed []byte, assetID uint32, form *core.WalletForm) ([]byte, error) {
	seed, pw, err := assetSeedAndPass(assetID, appSeed)
	if err != nil {
		return nil, err
	}
	defer encode.ClearBytes(seed)
	if err = asset.CreateWallet(assetID, &asset.CreateWalletParams{
		Type:     form.Type,
		Seed:     seed,
		Pass:     pw,
		Settings: form.Config,
		DataDir:  "./",
		Net:      dex.Mainnet,
	}); err != nil {
		return nil, fmt.Errorf("Error creating wallet: %w", err)
	}

	return pw, nil
}

func assetSeedAndPass(assetID uint32, appSeed []byte) (seed, pass []byte, err error) {
	seed, pass = core.AssetSeedAndPass(assetID, appSeed)
	return seed, pass, nil
}
