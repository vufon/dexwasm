// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package eth

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func importKeyToKeyStore(ks *keystore.KeyStore, priv *ecdsa.PrivateKey, pw []byte) error {
	accounts := ks.Accounts()
	if len(accounts) == 0 {
		_, err := ks.ImportECDSA(priv, string(pw))
		return err
	} else if len(accounts) == 1 {
		address := crypto.PubkeyToAddress(priv.PublicKey)
		if !bytes.Equal(accounts[0].Address.Bytes(), address.Bytes()) {
			errMsg := "importKeyToKeyStore: attemping to import account to eth wallet: %v, " +
				"but node already contains imported account: %v"
			return fmt.Errorf(errMsg, address, accounts[0].Address)
		}
	} else {
		return fmt.Errorf("importKeyToKeyStore: eth wallet keystore contains %v accounts", accounts)
	}
	return nil
}

// accountCredentials captures the account-specific geth interfaces.
type accountCredentials struct {
	ks     *keystore.KeyStore
	acct   *accounts.Account
	addr   common.Address
	wallet accounts.Wallet
}

func pathCredentials(dir string) (*accountCredentials, error) {
	// TODO: Use StandardScryptN and StandardScryptP?
	return credentialsFromKeyStore(keystore.NewKeyStore(dir, keystore.LightScryptN, keystore.LightScryptP))

}

func credentialsFromKeyStore(ks *keystore.KeyStore) (*accountCredentials, error) {
	accts := ks.Accounts()
	if len(accts) != 1 {
		return nil, fmt.Errorf("unexpected number of accounts, %d", len(accts))
	}
	acct := accts[0]
	wallets := ks.Wallets()
	if len(wallets) != 1 {
		return nil, fmt.Errorf("unexpected number of wallets, %d", len(wallets))
	}
	return &accountCredentials{
		ks:     ks,
		acct:   &acct,
		addr:   acct.Address,
		wallet: wallets[0],
	}, nil
}

func signData(creds *accountCredentials, data []byte) (sig, pubKey []byte, err error) {
	h := crypto.Keccak256(data)
	sig, err = creds.ks.SignHash(*creds.acct, h)
	if err != nil {
		return nil, nil, err
	}
	if len(sig) != 65 {
		return nil, nil, fmt.Errorf("unexpected signature length %d", len(sig))
	}

	pubKey, err = recoverPubkey(h, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("SignMessage: error recovering pubkey %w", err)
	}

	// Lop off the "recovery id", since we already recovered the pub key and
	// it's not used for validation.
	sig = sig[:64]

	return
}
