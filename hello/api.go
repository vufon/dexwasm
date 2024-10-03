package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall/js"
	"time"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/client/db"
	"decred.org/dcrdex/client/mnemonic"
	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/encrypt"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrutil/v4"
	promise "github.com/nlepage/go-js-promise"
)

func main() {
	http.HandleFunc("/createNewWallet", func(res http.ResponseWriter, req *http.Request) {
		params := make(map[string]string)
		if err := json.NewDecoder(req.Body).Decode(&params); err != nil {
			panic(err)
		}
		res.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(res).Encode(createNewWallet()); err != nil {
			panic(err)
		}
	})

	Serve(nil)

	select {}
}

func createNewWallet() any {
	fmt.Println("createNewWallet")
	appSeed, _ := createWalletSeed()
	walletSeed, pass := AssetSeedAndPass(42, appSeed)
	crypter := encrypt.NewCrypter([]byte("Bibo.17061993@"))
	//TODO, update birthday of wallet
	bday := uint64(time.Now().Unix())
	fmt.Println("Check walletSeed: ", string(walletSeed))
	fmt.Println("Check pass: ", string(pass))
	//TODO, handler form config
	if err := asset.CreateWallet(42, &asset.CreateWalletParams{
		Type:     walletTypeSPV,
		Seed:     walletSeed,
		Pass:     pass,
		Birthday: bday,
		Settings: make(map[string]string),
		DataDir:  assetDataDirectory(42),
		Net:      dex.Mainnet,
		Logger:   nil,
	}); err != nil {
		return ResponseError(fmt.Sprintf("Error creating wallet: %w", err))
	}
	encPW, err := crypter.Encrypt(pass)
	if err != nil {
		return ResponseError(err.Error())
	}
	return ResponseSuccessfully("Create wallet successfully", db.Wallet{
		Type:        walletTypeSPV,
		AssetID:     42,
		Settings:    make(map[string]string),
		EncryptedPW: encPW,
		// Balance and Address are set after connect.
	})
}

const (
	legacySeedLength = 64
	walletTypeSPV    = "SPV"
)

type Balance struct {
	asset.Balance
	Stamp time.Time `json:"stamp"`
}

type ResponseData struct {
	Error bool
	Msg   string
	Data  interface{}
}

type Wallet struct {
	AssetID  uint32
	Type     string
	Settings map[string]string
	Balance  *Balance
	PW       []byte
	Address  string
	Disabled bool
}

var (
	defaultApplicationDirectory = dcrutil.AppDataDir("dexc", false)
	unbip                       = dex.BipIDSymbol
)

func prettyJson(input string) (string, error) {
	var raw any
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}

func ResponseError(msg string) ResponseData {
	return ResponseData{Error: true, Msg: msg}
}

func ResponseSuccessfully(msg string, data interface{}) ResponseData {
	return ResponseData{Error: false, Msg: msg, Data: data}
}

func assetDataDirectory(assetID uint32) string {
	defaultDBPath, _, _, _ := setNet(defaultApplicationDirectory, "mainnet")
	return filepath.Join(filepath.Dir(defaultDBPath), "assetdb", unbip(assetID))
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

func decodeSeedString(seedStr string) (seed []byte, bday time.Time, err error) {
	// See if it decodes as a mnemonic seed first.
	seed, bday, err = mnemonic.DecodeMnemonic(seedStr)
	if err != nil {
		// Is it an old-school hex seed?
		bday = time.Time{}
		seed, err = hex.DecodeString(strings.Join(strings.Fields(seedStr), ""))
		if err != nil {
			return nil, time.Time{}, errors.New("unabled to decode provided seed")
		}
		if len(seed) != legacySeedLength {
			return nil, time.Time{}, errors.New("decoded seed is wrong length")
		}
	}
	return
}

func createWalletSeed() ([]byte, string) {
	return mnemonic.New()
}

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

func Request(r js.Value) *http.Request {
	jsBody := js.Global().Get("Uint8Array").New(promise.Await(r.Call("arrayBuffer")))
	body := make([]byte, jsBody.Get("length").Int())
	js.CopyBytesToGo(body, jsBody)

	req := httptest.NewRequest(
		r.Get("method").String(),
		r.Get("url").String(),
		bytes.NewBuffer(body),
	)

	headersIt := r.Get("headers").Call("entries")
	for {
		e := headersIt.Call("next")
		if e.Get("done").Bool() {
			break
		}
		v := e.Get("value")
		req.Header.Set(v.Index(0).String(), v.Index(1).String())
	}

	return req
}

// ResponseRecorder uses httptest.ResponseRecorder to build a JS Response
type ResponseRecorder struct {
	*httptest.ResponseRecorder
}

// NewResponseRecorder returns a new ResponseRecorder
func NewResponseRecorder() ResponseRecorder {
	return ResponseRecorder{httptest.NewRecorder()}
}

// JSResponse builds and returns the equivalent JS Response
func (rr ResponseRecorder) JSResponse() js.Value {
	var res = rr.Result()

	var body js.Value = js.Undefined()
	if res.ContentLength != 0 {
		var b, err = ioutil.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}
		body = js.Global().Get("Uint8Array").New(len(b))
		js.CopyBytesToJS(body, b)
	}

	var init = make(map[string]interface{}, 2)

	if res.StatusCode != 0 {
		init["status"] = res.StatusCode
	}

	if len(res.Header) != 0 {
		var headers = make(map[string]interface{}, len(res.Header))
		for k := range res.Header {
			headers[k] = res.Header.Get(k)
		}
		init["headers"] = headers
	}

	return js.Global().Get("Response").New(body, init)
}

// Serve serves HTTP requests using handler or http.DefaultServeMux if handler is nil.
func Serve(handler http.Handler) func() {
	var h = handler
	if h == nil {
		h = http.DefaultServeMux
	}

	var prefix = js.Global().Get("wasmhttp").Get("path").String()
	for strings.HasSuffix(prefix, "/") {
		prefix = strings.TrimSuffix(prefix, "/")
	}

	if prefix != "" {
		var mux = http.NewServeMux()
		mux.Handle(prefix+"/", http.StripPrefix(prefix, h))
		h = mux
	}

	var cb = js.FuncOf(func(_ js.Value, args []js.Value) interface{} {
		var resPromise, resolve, reject = promise.New()

		go func() {
			defer func() {
				if r := recover(); r != nil {
					if err, ok := r.(error); ok {
						reject(fmt.Sprintf("wasmhttp: panic: %+v\n", err))
					} else {
						reject(fmt.Sprintf("wasmhttp: panic: %v\n", r))
					}
				}
			}()

			var res = NewResponseRecorder()

			h.ServeHTTP(res, Request(args[0]))

			resolve(res.JSResponse())
		}()

		return resPromise
	})

	js.Global().Get("wasmhttp").Call("setHandler", cb)

	return cb.Release
}
