// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"decred.org/dcrdex/client/app"
	"decred.org/dcrdex/client/asset"
	_ "decred.org/dcrdex/client/asset/importall"
	"decred.org/dcrdex/client/core"
	"decred.org/dcrdex/client/mm"
	"decred.org/dcrdex/client/mnemonic"
	"decred.org/dcrdex/client/rpcserver"
	"decred.org/dcrdex/client/webserver"
	"decred.org/dcrdex/dex"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrutil/v4"
)

// appName defines the application name.
const appName = "bisonw"

var (
	appCtx, cancel = context.WithCancel(context.Background())
	webserverReady = make(chan string, 1)
	log            dex.Logger
)

func parseChainParams(network dex.Network) (*chaincfg.Params, error) {
	// Get network settings. Zero value is mainnet, but unknown non-zero cfg.Net
	// is an error.
	switch network {
	case dex.Simnet:
		return chaincfg.SimNetParams(), nil
	case dex.Testnet:
		return chaincfg.TestNet3Params(), nil
	case dex.Mainnet:
		return chaincfg.MainNetParams(), nil
	default:
		return nil, fmt.Errorf("unknown network ID: %d", uint8(network))
	}
}

func AssetSeedAndPass(assetID uint32, appSeed []byte) ([]byte, []byte) {
	const accountBasedSeedAssetID = 60 // ETH
	seedAssetID := assetID
	if ai, _ := asset.Info(assetID); ai != nil && ai.IsAccountBased {
		seedAssetID = accountBasedSeedAssetID
	}
	// Tokens asset IDs shouldn't be passed in, but if they are, return the seed
	// for the parent ID.
	if tkn := asset.TokenInfo(assetID); tkn != nil {
		if ai, _ := asset.Info(tkn.ParentID); ai != nil {
			if ai.IsAccountBased {
				seedAssetID = accountBasedSeedAssetID
			}
		}
	}

	b := make([]byte, len(appSeed)+4)
	copy(b, appSeed)
	binary.BigEndian.PutUint32(b[len(appSeed):], seedAssetID)
	s := blake256.Sum256(b)
	p := blake256.Sum256(s[:])
	return s[:], p[:]
}

func assetDataDirectory(assetID uint32) string {
	defaultDBPath, _, _, _ := setNet(dcrutil.AppDataDir("dexc", false), "mainnet")
	return filepath.Join(filepath.Dir(defaultDBPath), "assetdb", dex.BipIDSymbol(assetID))
}

func setNet(applicationDirectory, net string) (dbPath, logPath, mmEventDBPath, mmCfgPath string) {
	netDirectory := filepath.Join(applicationDirectory, net)
	logDirectory := filepath.Join(netDirectory, "logs")
	logFilename := filepath.Join(logDirectory, "dexc.log")
	mmEventLogDBFilename := filepath.Join(netDirectory, "eventlog.db")
	mmCfgFilename := filepath.Join(netDirectory, "mm_cfg.json")
	err := os.MkdirAll(netDirectory, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create net directory: %v\n", err)
		os.Exit(1)
	}
	err = os.MkdirAll(logDirectory, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(netDirectory, "dexc.db"), logFilename, mmEventLogDBFilename, mmCfgFilename
}

func runCore(cfg *app.Config) error {
	defer cancel() // for the earliest returns
	seed, _ := mnemonic.New()
	walletSeed, pass := AssetSeedAndPass(42, seed)
	bday := uint64(time.Now().Unix())
	//TODO, handler form config
	if err := asset.CreateWallet(42, &asset.CreateWalletParams{
		Type:     "SPV",
		Seed:     walletSeed,
		Pass:     pass,
		Birthday: bday,
		Settings: make(map[string]string),
		DataDir:  assetDataDirectory(42),
		Net:      dex.Mainnet,
		Logger:   nil,
	}); err != nil {
		return fmt.Errorf("Error creating wallet: %w", err)
	}
	asset.SetNetwork(cfg.Net)

	// If explicitly running without web server then you must run the rpc
	// server.
	if cfg.NoWeb && !cfg.RPCOn {
		return fmt.Errorf("cannot run without web server unless --rpc is specified")
	}

	if cfg.CPUProfile != "" {
		var f *os.File
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			return fmt.Errorf("error starting CPU profiler: %w", err)
		}
		err = pprof.StartCPUProfile(f)
		if err != nil {
			return fmt.Errorf("error starting CPU profiler: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	// Initialize logging.
	utc := !cfg.LocalLogs
	logMaker, closeLogger := app.InitLogging(cfg.LogPath, cfg.DebugLevel, true, utc)
	defer closeLogger()
	log = logMaker.Logger("BW")
	log.Infof("%s version %v (Go version %s)", appName, app.Version, runtime.Version())
	if utc {
		log.Infof("Logging with UTC time stamps. Current local time is %v",
			time.Now().Local().Format("15:04:05 MST"))
	}
	log.Infof("bisonw starting for network: %s", cfg.Net)
	log.Infof("Swap locktimes config: maker %s, taker %s",
		dex.LockTimeMaker(cfg.Net), dex.LockTimeTaker(cfg.Net))

	defer func() {
		if pv := recover(); pv != nil {
			log.Criticalf("Uh-oh! \n\nPanic:\n\n%v\n\nStack:\n\n%v\n\n",
				pv, string(debug.Stack()))
		}
	}()

	// Prepare the Core.
	clientCore, err := core.New(cfg.Core(logMaker.Logger("CORE")))
	if err != nil {
		return fmt.Errorf("error creating client core: %w", err)
	}

	marketMaker, err := mm.NewMarketMaker(clientCore, cfg.MMConfig.EventLogDBPath, cfg.MMConfig.BotConfigPath, logMaker.Logger("MM"))
	if err != nil {
		return fmt.Errorf("error creating market maker: %w", err)
	}

	// Catch interrupt signal (e.g. ctrl+c), prompting to shutdown if the user
	// is logged in, and there are active orders or matches.
	killChan := make(chan os.Signal, 1)
	signal.Notify(killChan, os.Interrupt)
	go func() {
		for range killChan {
			if promptShutdown(clientCore) {
				log.Infof("Shutting down...")
				cancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientCore.Run(appCtx)
		cancel() // in the event that Run returns prematurely prior to context cancellation
	}()

	<-clientCore.Ready()

	var mmCM *dex.ConnectionMaster
	defer func() {
		log.Info("Exiting bisonw main.")
		cancel()  // no-op with clean rpc/web server setup
		wg.Wait() // no-op with clean setup and shutdown
		if mmCM != nil {
			mmCM.Wait()
		}
	}()

	if marketMaker != nil {
		mmCM = dex.NewConnectionMaster(marketMaker)
		if err := mmCM.ConnectOnce(appCtx); err != nil {
			return fmt.Errorf("Error connecting market maker")
		}
	}

	if cfg.RPCOn {
		rpcSrv, err := rpcserver.New(cfg.RPC(clientCore, marketMaker, logMaker.Logger("RPC")))
		if err != nil {
			return fmt.Errorf("failed to create rpc server: %w", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			cm := dex.NewConnectionMaster(rpcSrv)
			err := cm.Connect(appCtx)
			if err != nil {
				log.Errorf("Error starting rpc server: %v", err)
				cancel()
				return
			}
			cm.Wait()
		}()
	}

	if !cfg.NoWeb {
		webSrv, err := webserver.New(cfg.Web(clientCore, marketMaker, logMaker.Logger("WEB"), utc))
		if err != nil {
			return fmt.Errorf("failed creating web server: %w", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			cm := dex.NewConnectionMaster(webSrv)
			err := cm.Connect(appCtx)
			if err != nil {
				log.Errorf("Error starting web server: %v", err)
				cancel()
				return
			}
			webserverReady <- webSrv.Addr()
			cm.Wait()
		}()
	} else {
		close(webserverReady)
	}

	// Wait for everything to stop.
	wg.Wait()

	return nil
}

// promptShutdown checks if there are active orders and asks confirmation to
// shutdown if there are. The return value indicates if it is safe to stop Core
// or if the user has confirmed they want to shutdown with active orders.
func promptShutdown(clientCore *core.Core) bool {
	log.Infof("Attempting to logout...")
	// Do not allow Logout hanging to prevent shutdown.
	res := make(chan bool, 1)
	go func() {
		// Only block logout if err is ActiveOrdersLogoutErr.
		var ok bool
		err := clientCore.Logout()
		if err == nil {
			ok = true
		} else if !errors.Is(err, core.ActiveOrdersLogoutErr) {
			log.Errorf("Unexpected logout error: %v", err)
			ok = true
		} // else not ok => prompt
		res <- ok
	}()

	select {
	case <-time.After(10 * time.Second):
		log.Errorf("Timeout waiting for Logout. Allowing shutdown, but you likely have active orders!")
		return true // cancel all the contexts, hopefully breaking whatever deadlock
	case ok := <-res:
		if ok {
			return true
		}
	}

	fmt.Print("You have active orders. Shutting down now may result in failed swaps and account penalization.\n" +
		"Do you want to quit anyway? ('yes' to quit, or enter to abort shutdown): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan() // waiting for user input
	if err := scanner.Err(); err != nil {
		fmt.Printf("Input error: %v", err)
		return false
	}

	switch resp := strings.ToLower(scanner.Text()); resp {
	case "y", "yes":
		return true
	case "n", "no", "":
	default: // anything else aborts, but warn about it
		fmt.Printf("Unrecognized response %q. ", resp)
	}
	fmt.Println("Shutdown aborted.")
	return false
}
