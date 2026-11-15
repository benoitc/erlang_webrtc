// DTLS 1.2 peer for webrtc_dtls_interop_SUITE, on pion/dtls with
// connection IDs (RFC 9146).
//
//	piondtls server <listen addr> <cert.pem> <key.pem> [cid size]
//	piondtls client <addr> <cert.pem> <key.pem> [cid size]
//
// A cid size of -1 turns connection IDs off, 0 sends with the peer's CID
// but asks for none. Once connected it prints the exported
// EXTRACTOR-dtls_srtp keys, then the client sends "from pion" and
// prints what it gets back, the server prints what it gets and answers.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/pion/dtls/v3"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: piondtls server|client addr cert key [cid size]")
		os.Exit(2)
	}
	mode, addr, certFile, keyFile := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	cidSize := 8
	if len(os.Args) > 5 {
		n, err := strconv.Atoi(os.Args[5])
		check(err)
		cidSize = n
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	check(err)
	config := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		ClientAuth:             dtls.RequireAnyClientCert,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AES128_CM_HMAC_SHA1_80},
	}
	switch {
	case cidSize > 0:
		config.ConnectionIDGenerator = dtls.RandomCIDGenerator(cidSize)
	case cidSize == 0:
		config.ConnectionIDGenerator = dtls.OnlySendCIDGenerator()
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	check(err)
	var conn *dtls.Conn
	if mode == "server" {
		l, err := dtls.Listen("udp", udpAddr, config)
		check(err)
		fmt.Printf("LISTENING %s\n", l.Addr())
		c, err := l.Accept()
		check(err)
		conn = c.(*dtls.Conn)
	} else {
		conn, err = dtls.Dial("udp", udpAddr, config)
		check(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	check(conn.HandshakeContext(ctx))
	state, _ := conn.ConnectionState()
	keys, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 60)
	check(err)
	fmt.Printf("KEYS %s\n", hex.EncodeToString(keys))
	buf := make([]byte, 2048)
	check(conn.SetDeadline(time.Now().Add(10 * time.Second)))
	if mode == "server" {
		n, err := conn.Read(buf)
		check(err)
		fmt.Printf("GOT %s\n", buf[:n])
		_, err = conn.Write([]byte("from pion"))
		check(err)
	} else {
		_, err = conn.Write([]byte("from pion"))
		check(err)
		n, err := conn.Read(buf)
		check(err)
		fmt.Printf("GOT %s\n", buf[:n])
	}
	time.Sleep(200 * time.Millisecond)
	_ = conn.Close()
}

func check(err error) {
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		os.Exit(1)
	}
}
