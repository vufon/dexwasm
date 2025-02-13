// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package bolt

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dexdb "decred.org/dcrdex/client/db"
	"decred.org/dcrdex/dex/order"
	"go.etcd.io/bbolt"
)

var dbUpgradeTests = [...]struct {
	name       string
	upgrade    upgradefunc
	verify     func(*testing.T, *bbolt.DB)
	filename   string // in testdata directory
	newVersion uint32
}{
	// {"testnetbot", v4Upgrade, verifyV4Upgrade, "dexbot-testnet.db.gz", 6}, // only for TestUpgradeDB, using just filename
	{"upgradeFromV0", v1Upgrade, verifyV1Upgrade, "v0.db.gz", 1},
	{"upgradeFromV1", v2Upgrade, verifyV2Upgrade, "v1.db.gz", 2},
	{"upgradeFromV2", v3Upgrade, verifyV3Upgrade, "v2.db.gz", 3},
	{"upgradeFromV3", v4Upgrade, verifyV4Upgrade, "v3.db.gz", 4},
	{"upgradeFromV4", v5Upgrade, verifyV5Upgrade, "v4.db.gz", 5},
	{"upgradeFromV5", v6Upgrade, verifyV6Upgrade, "v5.db.gz", 6},
}

func TestUpgrades(t *testing.T) {
	upgradeLog = tLogger
	t.Run("group", func(t *testing.T) {
		for _, tc := range dbUpgradeTests {
			tc := tc // capture range variable
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				dbPath := unpack(t, tc.filename)
				db, err := bbolt.Open(dbPath, 0600,
					&bbolt.Options{Timeout: 1 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				err = db.Update(func(dbtx *bbolt.Tx) error {
					return doUpgrade(dbtx, tc.upgrade, tc.newVersion)
				})
				if err != nil {
					t.Fatalf("Upgrade %d -> %d failed: %v", tc.newVersion-1, tc.newVersion, err)
				}
				tc.verify(t, db)
			})
		}
	})
}

func TestUpgradeDB(t *testing.T) {
	runUpgrade := func(archiveName string) error {
		dbPath := unpack(t, archiveName)
		// NewDB runs upgradeDB.
		dbi, err := NewDB(dbPath, tLogger)
		if err != nil {
			return fmt.Errorf("database initialization or upgrade error: %w", err)
		}
		db := dbi.(*BoltDB)
		// Run upgradeDB again and it should be happy.
		err = db.upgradeDB()
		if err != nil {
			return fmt.Errorf("upgradeDB error: %v", err)
		}
		newVersion, err := db.getVersion()
		if err != nil {
			return fmt.Errorf("getVersion error: %v", err)
		}
		if newVersion != DBVersion {
			return fmt.Errorf("DB version not set. Expected %d, got %d", DBVersion, newVersion)
		}
		return nil
	}

	for _, tt := range dbUpgradeTests {
		err := runUpgrade(tt.filename)
		if err != nil {
			t.Fatalf("upgrade error for version %d database: %v", tt.newVersion-1, err)
		}
	}

}

func verifyV1Upgrade(t *testing.T, db *bbolt.DB) {
	t.Helper()
	err := db.View(func(dbtx *bbolt.Tx) error {
		return checkVersion(dbtx, 1)
	})
	if err != nil {
		t.Error(err)
	}
}

func verifyV2Upgrade(t *testing.T, db *bbolt.DB) {
	t.Helper()
	maxFeeB := uint64Bytes(^uint64(0))
	ordersBucket := []byte("orders")

	err := db.View(func(dbtx *bbolt.Tx) error {
		err := checkVersion(dbtx, 2)
		if err != nil {
			return err
		}

		master := dbtx.Bucket(ordersBucket)
		if master == nil {
			return fmt.Errorf("orders bucket not found")
		}
		return master.ForEach(func(oid, _ []byte) error {
			oBkt := master.Bucket(oid)
			if oBkt == nil {
				return fmt.Errorf("order %x bucket is not a bucket", oid)
			}
			if !bytes.Equal(oBkt.Get(maxFeeRateKey), maxFeeB) {
				return fmt.Errorf("max fee not upgraded")
			}
			return nil
		})
	})
	if err != nil {
		t.Error(err)
	}
}

// Nothing to really check here. Any errors would have come out during the
// upgrade process itself, since we just added a default nil field.
func verifyV3Upgrade(t *testing.T, db *bbolt.DB) {
	t.Helper()
	err := db.View(func(dbtx *bbolt.Tx) error {
		return checkVersion(dbtx, 3)
	})
	if err != nil {
		t.Error(err)
	}
}

func verifyV4Upgrade(t *testing.T, db *bbolt.DB) {
	oldOrdersBucket := []byte("orders")
	newActiveOrdersBucket := []byte("activeOrders")
	err := db.View(func(dbtx *bbolt.Tx) error {
		err := checkVersion(dbtx, 4)
		if err != nil {
			return err
		}
		// Ensure we have both old and new buckets.
		archivedOrdersBkt := dbtx.Bucket(oldOrdersBucket)
		if archivedOrdersBkt == nil {
			return fmt.Errorf("archived orders bucket not found")
		}
		activeOrdersBkt := dbtx.Bucket(newActiveOrdersBucket)
		if activeOrdersBkt == nil {
			return fmt.Errorf("active orders bucket not found")
		}

		// Ensure the old bucket now only contains finished orders.
		err = archivedOrdersBkt.ForEach(func(k, _ []byte) error {
			archivedOBkt := archivedOrdersBkt.Bucket(k)
			if archivedOBkt == nil {
				return fmt.Errorf("order %x bucket is not a bucket", k)
			}
			status := order.OrderStatus(intCoder.Uint16(archivedOBkt.Get(statusKey)))
			if status == order.OrderStatusUnknown {
				fmt.Printf("Encountered order with unknown status: %x\n", k)
				return nil
			}
			if status.IsActive() {
				return fmt.Errorf("archived bucket has active order: %x", k)
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Ensure the new bucket only contains active orders.
		err = activeOrdersBkt.ForEach(func(k, _ []byte) error {
			activeOBkt := activeOrdersBkt.Bucket(k)
			if activeOBkt == nil {
				return fmt.Errorf("order %x bucket is not a bucket", k)
			}
			status := order.OrderStatus(intCoder.Uint16(activeOBkt.Get(statusKey)))
			if status == order.OrderStatusUnknown {
				return fmt.Errorf("encountered order with unknown status: %x", k)
			}
			if !status.IsActive() {
				return fmt.Errorf("active orders bucket has archived order: %x", k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

// Ensure that the LegacyEncKey field is populated for the accounts in the DB.
func verifyV5Upgrade(t *testing.T, db *bbolt.DB) {
	if err := db.View(func(tx *bbolt.Tx) error {
		return checkVersion(tx, 5)
	}); err != nil {
		t.Error(err)
	}

	if err := db.View(func(tx *bbolt.Tx) error {
		accts := tx.Bucket(accountsBucket)
		c := accts.Cursor()
		for acctKey, _ := c.First(); acctKey != nil; acctKey, _ = c.Next() {
			acct := accts.Bucket(acctKey)
			if acct == nil {
				return fmt.Errorf("account bucket %s value not a nested bucket", string(acctKey))
			}
			acctB := getCopy(acct, accountKey)
			if acctB == nil {
				return fmt.Errorf("empty account found for %s", string(acctKey))
			}
			acctInfo, err := dexdb.DecodeAccountInfo(acctB)
			if err != nil {
				return err
			}
			if len(acctInfo.LegacyEncKey) == 0 {
				return errors.New("LegacyEncKey not sets")
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

func verifyV6Upgrade(t *testing.T, db *bbolt.DB) {
	verifyMatches := map[string]bool{ // matchid: active
		"52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649": true,  // status < MatchComplete, not revoked, not refunded
		"81855a1e00167939cb6694d2c422acd208a0072939487f6999eb9d18a4478404": false, // status < MatchComplete, revoked at NewlyMatched
		"5d87f3c67cf2367951baa2ff6cd471c483f15fb90badb37c5821b6d95526a41a": true,  // status == MakerSwapCast, side Maker, revoked, requires refund
		"9504680b4e7c8b763a1b1d49d4955c8486216325253fec738dd7a9e28bf92111": false, // status == TakerSwapCast, side Maker, revoked, refunded
		"9c160f0702448615bbda08313f6a8eb668d20bf5059875921e668a5bdf2c7fc4": true,  // status == MatchComplete, no RedeemSig !!! TODO: missing InitSig
		"844592d2572bcd0668d2d6c52f5054e2d0836bf84c7174cb7476364cc3dbd968": false, // status == MatchComplete, RedeemSig set
		"b0f7172ed85794bb358b0c3b525da1786f9fff094279db1944ebd7a19d0f7bba": false, // cancel order match
	}

	bdb := &BoltDB{DB: db}
	err := bdb.matchesView(func(mb, amb *bbolt.Bucket) error {
		// active matches
		err := mb.ForEach(func(k, _ []byte) error {
			matchID := hex.EncodeToString(k)
			mBkt := mb.Bucket(k)
			if mBkt == nil {
				return fmt.Errorf("match %s bucket is not a bucket", matchID)
			}
			midB := getCopy(mBkt, matchIDKey)
			if midB == nil {
				return fmt.Errorf("nil match ID bytes")
			}
			mid := hex.EncodeToString(midB)
			if active, found := verifyMatches[mid]; !found {
				return fmt.Errorf("match %v not found in test DB", mid)
			} else if !active {
				return fmt.Errorf("inactive match found in active matches bucket: %v", mid)
			}
			return nil
		})
		if err != nil {
			return err
		}

		// archived
		return amb.ForEach(func(k, _ []byte) error {
			matchID := hex.EncodeToString(k)
			mBkt := amb.Bucket(k)
			if mBkt == nil {
				return fmt.Errorf("match %s bucket is not a bucket", matchID)
			}
			midB := getCopy(mBkt, matchIDKey)
			if midB == nil {
				return fmt.Errorf("nil match ID bytes")
			}
			mid := hex.EncodeToString(midB)
			if active, found := verifyMatches[mid]; !found {
				return fmt.Errorf("match %v not found in test DB", mid)
			} else if active {
				return fmt.Errorf("active match found in archived matches bucket: %v", mid)
			}
			return nil
		})
	})
	if err != nil {
		t.Error(err)
	}
}

func checkVersion(dbtx *bbolt.Tx, expectedVersion uint32) error {
	bkt := dbtx.Bucket(appBucket)
	if bkt == nil {
		return fmt.Errorf("appBucket not found")
	}
	versionB := bkt.Get(versionKey)
	if versionB == nil {
		return fmt.Errorf("expected a non-nil version value")
	}
	version := intCoder.Uint32(versionB)
	if version != expectedVersion {
		return fmt.Errorf("expected db version %d, got %d",
			expectedVersion, version)
	}
	return nil
}

func unpack(t *testing.T, db string) string {
	t.Helper()
	d := t.TempDir()

	t.Helper()
	archive, err := os.Open(filepath.Join("testdata", db))
	if err != nil {
		t.Fatal(err)
	}

	r, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(d, strings.TrimSuffix(db, ".gz"))
	dbFile, err := os.Create(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(dbFile, r)
	archive.Close()
	dbFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	return dbPath
}
