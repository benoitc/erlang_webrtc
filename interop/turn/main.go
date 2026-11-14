// Minimal TURN server (RFC 8656, UDP) built on pion/turn, used by the
// erlang_webrtc test suites as an independent relay implementation.
//
// Usage: turn-server -listen 127.0.0.1:0 -user test=secret -realm webrtc
// Prints "listening <ip:port>" on stdout once ready.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pion/turn/v5"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	users := flag.String("user", "test=secret", "comma separated user=password")
	realm := flag.String("realm", "webrtc", "realm")
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
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			k, ok := keys[ra.Username]
			return ra.Username, k, ok
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(host),
				Address:      host,
			},
		}},
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
