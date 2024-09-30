package wasmhttp

import (
	"crypto"
	"encoding/hex"
	"syscall/js"

	"decred.org/dcrdex/client/core"
)

func Hash(this js.Value, args []js.Value) interface{} {
	h := crypto.SHA512.New()
	h.Write([]byte(args[0].String()))
	return hex.EncodeToString(h.Sum(nil))
}

func CreateWallet(this js.Value, args []js.Value) interface{} {
	core := core.Core{}
	return core.CreateWallet([]byte("appPassword"), []byte("walletPassword"), nil)
}
