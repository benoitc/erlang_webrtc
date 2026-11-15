// Minimal TURN server (RFC 8656) built on pion/turn, used by the
// erlang_webrtc test suites as an independent relay implementation.
// Clients reach it over UDP, and optionally TCP and TLS (RFC 8656 §3.1);
// relays are always UDP.
//
// Usage: turn-server -listen 127.0.0.1:0 -user test=secret -realm webrtc
//
//	[-tcp 127.0.0.1:0] [-tls 127.0.0.1:0 -tls-ca ca.pem]
//
// Prints "listening-tcp <ip:port>" and "listening-tls <ip:port>" for the
// stream listeners, then "listening <ip:port>" (UDP) once ready. With
// -tls the server uses a fresh certificate for 127.0.0.1 and localhost
// from a fresh CA, written as PEM to the -tls-ca file so clients can
// trust it.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pion/turn/v5"
)

// testCertificate returns a server certificate for 127.0.0.1 and
// localhost, signed by a fresh CA, and the CA certificate in PEM.
func testCertificate() (tls.Certificate, []byte) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "erlang-webrtc test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	ca, _ := x509.ParseCertificate(caDer)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDer}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	users := flag.String("user", "test=secret", "comma separated user=password")
	realm := flag.String("realm", "webrtc", "realm")
	tcpAddr := flag.String("tcp", "", "TCP listen address (none when empty)")
	tlsAddr := flag.String("tls", "", "TLS listen address (none when empty)")
	tlsCA := flag.String("tls-ca", "", "file to write the TLS certificate to")
	flag.Parse()

	conn, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	keys := map[string][]byte{}
	for _, kv := range strings.Split(*users, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			keys[parts[0]] = turn.GenerateAuthKey(parts[0], *realm, parts[1])
		}
	}
	host, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	relay := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP(host), Address: host}
	var listeners []turn.ListenerConfig
	if *tcpAddr != "" {
		l, err := net.Listen("tcp4", *tcpAddr)
		if err != nil {
			log.Fatalf("listen tcp: %v", err)
		}
		listeners = append(listeners, turn.ListenerConfig{Listener: l, RelayAddressGenerator: relay})
		fmt.Printf("listening-tcp %s\n", l.Addr().String())
	}
	if *tlsAddr != "" {
		cert, pemBytes := testCertificate()
		if *tlsCA != "" {
			if err := os.WriteFile(*tlsCA, pemBytes, 0o644); err != nil {
				log.Fatalf("write ca: %v", err)
			}
		}
		l, err := tls.Listen("tcp4", *tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			log.Fatalf("listen tls: %v", err)
		}
		listeners = append(listeners, turn.ListenerConfig{Listener: l, RelayAddressGenerator: relay})
		fmt.Printf("listening-tls %s\n", l.Addr().String())
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			k, ok := keys[ra.Username]
			return ra.Username, k, ok
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            conn,
			RelayAddressGenerator: relay,
		}},
		ListenerConfigs: listeners,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	fmt.Printf("listening %s\n", conn.LocalAddr().String())
	os.Stdout.Sync()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		// Exit when the controller closes stdin.
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		sig <- syscall.SIGTERM
	}()
	<-sig
	server.Close()
}
