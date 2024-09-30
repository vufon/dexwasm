// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package main

import (
	"context"
	"fmt"
	"os"
	"syscall/js"

	_ "decred.org/dcrdex/client/asset/importall"
	"decred.org/dcrdex/client/cmd/wasmhttp"
	"decred.org/dcrdex/client/core"
	"decred.org/dcrdex/client/mm"
	"decred.org/dcrdex/client/webserver"
	"decred.org/dcrdex/dex"
)

// appName defines the application name.
const appName = "bisonw"

var (
	appCtx, cancel = context.WithCancel(context.Background())
	webserverReady = make(chan string, 1)
	log            dex.Logger
)

func main() {
	err := runCore()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runCore() error {
	//create core
	// Prepare the Core.
	clientCore, err := core.New(CoreConfig())
	if err != nil {
		return fmt.Errorf("error creating client core: %w", err)
	}
	//create new market maker
	marketMaker, err := mm.NewMarketMaker(clientCore, "", "", nil)
	if err != nil {
		return fmt.Errorf("error creating market maker: %w", err)
	}

	webSrv, err := webserver.New(
		&webserver.Config{
			Core:        clientCore,
			MarketMaker: marketMaker,
			Addr:        "",
		},
	)
	if err != nil {
		return fmt.Errorf("failed creating web server: %w", err)
	}
	done := make(chan struct{}, 0)
	js.Global().Set("createWallet", js.FuncOf(wasmhttp.CreateWallet))
	<-done
	return nil
}

func CoreConfig() *core.Config {
	//TODO set config info for core
	return &core.Config{}
}
