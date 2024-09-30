package comms

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/msgjson"
	"github.com/decred/dcrd/certgen"
	"github.com/gorilla/websocket"
)

var tLogger = dex.StdOutLogger("conn_TEST", dex.LevelTrace)

func makeRequest(id uint64, route string, msg any) *msgjson.Message {
	req, _ := msgjson.NewRequest(id, route, msg)
	return req
}

// genCertPair generates a key/cert pair to the paths provided.
func genCertPair(certFile, keyFile string, altDNSNames []string) error {
	tLogger.Infof("Generating TLS certificates...")

	org := "dcrdex autogenerated cert"
	validUntil := time.Now().Add(10 * 365 * 24 * time.Hour)
	cert, key, err := certgen.NewTLSCertPair(elliptic.P521(), org,
		validUntil, altDNSNames)
	if err != nil {
		return err
	}

	// Write cert and key files.
	if err = os.WriteFile(certFile, cert, 0644); err != nil {
		return err
	}
	if err = os.WriteFile(keyFile, key, 0600); err != nil {
		os.Remove(certFile)
		return err
	}

	tLogger.Infof("Done generating TLS certificates")
	return nil
}

func TestWsConn(t *testing.T) {
	// Must wait for goroutines, especially the ones that capture t.
	var wg sync.WaitGroup
	defer wg.Wait()

	upgrader := websocket.Upgrader{}

	pingCh := make(chan struct{})
	readPumpCh := make(chan any)
	writePumpCh := make(chan *msgjson.Message)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type conn struct {
		sync.WaitGroup
		*websocket.Conn
	}
	var clientMtx sync.Mutex
	clients := make(map[uint64]*conn)

	// server.Shutdown does not wait for hijacked connections, and pong handler
	// uses t.Logf.
	defer func() {
		clientMtx.Lock()
		for id, h := range clients {
			h.Close()
			h.Wait()
			delete(clients, id)
		}
		clientMtx.Unlock()
	}()

	var id uint64
	// server's "/ws" handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Helper()
		id := atomic.AddUint64(&id, 1) // shadow id
		hCtx, hCancel := context.WithCancel(ctx)

		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("unable to upgrade http connection: %s", err)
		}

		ch := &conn{Conn: c}
		clientMtx.Lock()
		clients[id] = ch
		clientMtx.Unlock()

		c.SetPongHandler(func(string) error {
			t.Logf("handler #%d: pong received", id)
			return nil
		})

		ch.Add(1)
		go func() {
			defer ch.Done()
			for {
				select {
				case <-pingCh:
					err := c.WriteControl(websocket.PingMessage, []byte{},
						time.Now().Add(writeWait))
					if err != nil {
						if hCtx.Err() == nil {
							// Only a failure if the server isn't shutting down.
							t.Errorf("handler #%d: ping error: %v", id, err)
						}
						return
					}

					t.Logf("handler #%d: ping sent", id)

				case msg := <-readPumpCh:
					err := c.WriteJSON(msg)
					if err != nil {
						t.Errorf("handler #%d: write error: %v", id, err)
						return
					}

				case <-hCtx.Done():
					return
				}
			}
		}()

		ch.Add(1)
		go func() {
			defer ch.Done()
			for {
				mType, message, err := c.ReadMessage()
				if err != nil {
					hCancel()
					c.Close()

					// If the context has been canceled, don't do anything.
					if hCtx.Err() != nil {
						return
					}

					if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
						// Terminate on a normal close message.
						return
					}

					t.Errorf("handler #%d: read error: %v\n", id, err)
					return
				}

				if mType == websocket.TextMessage {
					msg, err := msgjson.DecodeMessage(message)
					if err != nil {
						t.Errorf("handler #%d: decode error: %v", id, err)
						continue // Don't hang up.
					}

					writePumpCh <- msg
				}
			}
		}()
	}

	certFile, err := os.CreateTemp("", "certfile")
	if err != nil {
		t.Fatalf("unable to create temp certfile: %s", err)
	}
	certFile.Close()
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "keyfile")
	if err != nil {
		t.Fatalf("unable to create temp keyfile: %s", err)
	}
	keyFile.Close()
	defer os.Remove(keyFile.Name())

	err = genCertPair(certFile.Name(), keyFile.Name(), nil)
	if err != nil {
		t.Fatal(err)
	}

	certB, err := os.ReadFile(certFile.Name())
	if err != nil {
		t.Fatalf("file reading error: %v", err)
	}

	host := "127.0.0.1:0"
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", handler)

	// http server for the connect and upgrade
	server := &http.Server{
		WriteTimeout: time.Second * 10,
		ReadTimeout:  time.Second * 10,
		Addr:         host,
		Handler:      mux,
	}
	defer server.Shutdown(context.Background())

	wg.Add(1)
	serverReady := make(chan error, 1)
	go func() {
		defer wg.Done()

		ln, err := net.Listen("tcp", server.Addr)
		if err != nil {
			serverReady <- err
			return
		}
		defer ln.Close()
		//log.Info(ln.Addr().(*net.TCPAddr).Port)
		host = ln.Addr().String()
		serverReady <- nil // after setting host

		err = server.ServeTLS(ln, certFile.Name(), keyFile.Name())
		if err != nil {
			fmt.Println(err)
		}
	}()

	// wait for server to start listening before connecting
	err = <-serverReady
	if err != nil {
		t.Fatal(err)
	}

	const pingWait = 500 * time.Millisecond
	setupWsConn := func(cert []byte) (*wsConn, error) {
		cfg := &WsCfg{
			URL:      "wss://" + host + "/ws",
			PingWait: pingWait,
			Cert:     cert,
			Logger:   tLogger,
		}
		conn, err := NewWsConn(cfg)
		if err != nil {
			return nil, err
		}
		return conn.(*wsConn), nil
	}

	// test no cert error
	noCertConn, err := setupWsConn(nil)
	if err != nil {
		t.Fatal(err)
	}
	noCertConnMaster := dex.NewConnectionMaster(noCertConn)
	err = noCertConnMaster.Connect(ctx)
	noCertConnMaster.Disconnect()
	if err == nil || !errors.Is(err, ErrCertRequired) {
		t.Fatalf("failed to get ErrCertRequired for no cert connection, got %v", err)
	}

	// test invalid cert error
	_, err = setupWsConn([]byte("invalid cert"))
	if err == nil || !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("failed to get ErrInvalidCert for invalid cert connection, got %v", err)
	}

	// connect with cert
	wsc, err := setupWsConn(certB)
	if err != nil {
		t.Fatal(err)
	}
	waiter := dex.NewConnectionMaster(wsc)
	err = waiter.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	reconnectAndPing := func() {
		// Drop the connection and force a reconnect by waiting longer than the
		// read deadline (the ping wait), plus a bit extra to allow the timeout
		// to flip off the connection and queue a reconnect.
		time.Sleep(pingWait * 3 / 2)
		runtime.Gosched()

		// Wait for a reconnection.
		for wsc.IsDown() {
			time.Sleep(time.Millisecond * 10)
			continue
		}

		// Send a ping.
		pingCh <- struct{}{}
	}

	orderid, _ := hex.DecodeString("ceb09afa675cee31c0f858b94c81bd1a4c2af8c5947d13e544eef772381f2c8d")
	matchid, _ := hex.DecodeString("7c6b44735e303585d644c713fe0e95897e7e8ba2b9bba98d6d61b70006d3d58c")
	match := &msgjson.Match{
		OrderID:  orderid,
		MatchID:  matchid,
		Quantity: 20,
		Rate:     2,
		Address:  "DsiNAJCd2sSazZRU9ViDD334DaLgU1Kse3P",
	}

	// Ensure a malformed message to the client does not terminate
	// the connection.
	readPumpCh <- []byte("{notjson")

	// Send a message to the client.
	sent := makeRequest(1, msgjson.MatchRoute, match)
	readPumpCh <- sent

	// Fetch the read source.
	readSource := wsc.MessageSource()
	if readSource == nil {
		t.Fatal("expected a non-nil read source")
	}

	// Read the message received by the client.
	received := <-readSource

	// Ensure the received message equal to the sent message.
	if received.Type != sent.Type {
		t.Fatalf("expected %v type, got %v", sent.Type, received.Type)
	}

	if received.Route != sent.Route {
		t.Fatalf("expected %v route, got %v", sent.Route, received.Route)
	}

	if received.ID != sent.ID {
		t.Fatalf("expected %v id, got %v", sent.ID, received.ID)
	}

	if !bytes.Equal(received.Payload, sent.Payload) {
		t.Fatal("sent and received payload mismatch")
	}

	reconnectAndPing()

	coinID := []byte{
		0xc3, 0x16, 0x10, 0x33, 0xde, 0x09, 0x6f, 0xd7, 0x4d, 0x90, 0x51, 0xff,
		0x0b, 0xd9, 0x9e, 0x35, 0x9d, 0xe3, 0x50, 0x80, 0xa3, 0x51, 0x10, 0x81,
		0xed, 0x03, 0x5f, 0x54, 0x1b, 0x85, 0x0d, 0x43, 0x00, 0x00, 0x00, 0x0a,
	}

	contract, _ := hex.DecodeString("caf8d277f80f71e4")
	init := &msgjson.Init{
		OrderID:  orderid,
		MatchID:  matchid,
		CoinID:   coinID,
		Contract: contract,
	}

	// Send a message from the client.
	mId := wsc.NextID()
	sent = makeRequest(mId, msgjson.InitRoute, init)
	handlerRun := false
	err = wsc.Request(sent, func(*msgjson.Message) {
		handlerRun = true
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read the message received by the server.
	received = <-writePumpCh

	// Ensure the received message equal to the sent message.
	if received.Type != sent.Type {
		t.Fatalf("expected %v type, got %v", sent.Type, received.Type)
	}

	if received.Route != sent.Route {
		t.Fatalf("expected %v route, got %v", sent.Route, received.Route)
	}

	if received.ID != sent.ID {
		t.Fatalf("expected %v id, got %v", sent.ID, received.ID)
	}

	if !bytes.Equal(received.Payload, sent.Payload) {
		t.Fatal("sent and received payload mismatch")
	}

	// Ensure the next id is as expected.
	next := wsc.NextID()
	if next != 2 {
		t.Fatalf("expected next id to be %d, got %d", 2, next)
	}

	// Ensure the request got logged, also unregister the response handler.
	hndlr := wsc.respHandler(mId)
	if hndlr == nil {
		t.Fatalf("no handler found")
	}
	hndlr.f(nil)
	if !handlerRun {
		t.Fatalf("wrong handler retrieved")
	}

	// Ensure the response handler is unlogged.
	hndlr = wsc.respHandler(mId)
	if hndlr != nil {
		t.Fatal("found a response handler for an unlogged request id")
	}

	pingCh <- struct{}{}

	// Ensure malformed request data (a send failure) does not leave a
	// registered response handler or kill the connection.
	sent.ID = wsc.NextID()
	sent.Payload = []byte("{notjson")
	err = wsc.Request(sent, func(*msgjson.Message) {})
	if err == nil {
		t.Fatalf("expected error with malformed request payload")
	}

	// Ensure the response handler is unregistered.
	if wsc.respHandler(mId) != nil {
		t.Fatal("response handler was still registered")
	}

	// New request to test expiration.
	mId = next
	sent = makeRequest(mId, msgjson.InitRoute, init)
	expiring := make(chan struct{}, 1)
	expTime := 50 * time.Millisecond // way shorter than pingWait
	err = wsc.RequestWithTimeout(sent, func(*msgjson.Message) {}, expTime, func() {
		expiring <- struct{}{}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	<-writePumpCh

	pingCh <- struct{}{}

	// Yield to the comms goroutine in case this machine is poor.
	runtime.Gosched()
	select {
	case <-expiring:
	case <-time.NewTimer(time.Second).C: // >> expTime
		t.Fatalf("didn't expire") // conn will be dead by this time without pings
	}

	// New request to abort on conn shutdown.
	sent = makeRequest(wsc.NextID(), msgjson.InitRoute, init)
	expiring = make(chan struct{}, 1)
	expTime = 20 * time.Second                  // we're going to cancel first
	beforeExpire := time.After(2 * time.Second) // enough time for shutdown to call expire func
	err = wsc.RequestWithTimeout(sent, func(*msgjson.Message) {}, expTime, func() {
		expiring <- struct{}{}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	<-writePumpCh

	pingCh <- struct{}{}

	// Shutdown/Disconnect before expire.
	time.Sleep(50 * time.Millisecond) // let pings and pongs flush, but it's not a problem if they bomb
	waiter.Disconnect()

	select {
	case <-beforeExpire: // much shorter than req timeout
		t.Error("expire func not called on conn shutdown")
	case <-expiring: // means aborted if triggered before timeout
	}

	select {
	case _, ok := <-readSource:
		if ok {
			t.Error("read source should have been closed")
		}
	default:
		t.Error("read source should have been closed")
	}
}
