// Pion WebRTC peer adapter for the erlang_webrtc interop suite.
// Speaks the line-delimited JSON protocol described in ../PROTOCOL.md.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/pion/ice/v4"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

type channelSpec struct {
	Label             string  `json:"label"`
	Ordered           *bool   `json:"ordered"`
	MaxRetransmits    *uint16 `json:"max_retransmits"`
	MaxPacketLifeTime *uint16 `json:"max_packet_life_time"`
	Negotiated        bool    `json:"negotiated"`
	ID                *uint16 `json:"id"`
	Protocol          string  `json:"protocol"`
}

type command struct {
	Cmd        string        `json:"cmd"`
	Media      []string      `json:"media"`
	Channels   []channelSpec `json:"channels"`
	IceRestart bool          `json:"ice_restart"`
	Type       string        `json:"type"`
	SDP        string        `json:"sdp"`
	Candidate  string        `json:"candidate"`
	Mid        string        `json:"mid"`
	Label      string        `json:"label"`
	Data       string        `json:"data"`
	Binary     bool          `json:"binary"`
	AllIfaces  bool          `json:"all_interfaces"`
	channelSpec
}

var (
	outMu    sync.Mutex
	out      = json.NewEncoder(os.Stdout)
	pc       *webrtc.PeerConnection
	chMu     sync.Mutex
	channels = map[string]*webrtc.DataChannel{}
	tracks   = map[string]*webrtc.TrackLocalStaticRTP{}
)

func emit(ev map[string]any) {
	outMu.Lock()
	defer outMu.Unlock()
	if err := out.Encode(ev); err != nil {
		log.Printf("emit: %v", err)
	}
}

func fail(err error) {
	emit(map[string]any{"event": "error", "message": err.Error()})
}

func main() {
	log.SetOutput(os.Stderr)
	emit(map[string]any{"event": "ready", "implementation": "pion", "version": "v4.2.26"})
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var c command
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			fail(err)
			continue
		}
		if err := handle(c); err != nil {
			fail(fmt.Errorf("%s: %w", c.Cmd, err))
		}
		if c.Cmd == "close" {
			return
		}
	}
}

func handle(c command) error {
	switch c.Cmd {
	case "init":
		return initPC(c)
	case "create_offer":
		offer, err := pc.CreateOffer(&webrtc.OfferOptions{ICERestart: c.IceRestart})
		if err != nil {
			return err
		}
		if err := pc.SetLocalDescription(offer); err != nil {
			return err
		}
		emit(map[string]any{"event": "local_description", "type": "offer", "sdp": pc.LocalDescription().SDP})
	case "remote_description":
		desc := webrtc.SessionDescription{SDP: c.SDP, Type: webrtc.NewSDPType(c.Type)}
		if err := pc.SetRemoteDescription(desc); err != nil {
			return err
		}
		if desc.Type == webrtc.SDPTypeOffer {
			answer, err := pc.CreateAnswer(nil)
			if err != nil {
				return err
			}
			if err := pc.SetLocalDescription(answer); err != nil {
				return err
			}
			emit(map[string]any{"event": "local_description", "type": "answer", "sdp": pc.LocalDescription().SDP})
		}
	case "remote_candidate":
		if c.Candidate == "" {
			return nil
		}
		mid := c.Mid
		return pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: c.Candidate, SDPMid: &mid})
	case "send":
		chMu.Lock()
		dc := channels[c.Label]
		chMu.Unlock()
		if dc == nil {
			return fmt.Errorf("no channel %q", c.Label)
		}
		if c.Binary {
			b, err := base64.StdEncoding.DecodeString(c.Data)
			if err != nil {
				return err
			}
			return dc.Send(b)
		}
		return dc.SendText(c.Data)
	case "create_channel":
		return createChannel(c.channelSpec)
	case "close_channel":
		chMu.Lock()
		dc := channels[c.Label]
		chMu.Unlock()
		if dc != nil {
			return dc.Close()
		}
	case "stats":
		emit(map[string]any{"event": "stats", "stats": pc.GetStats()})
	case "close":
		return pc.Close()
	default:
		return fmt.Errorf("unknown command")
	}
	return nil
}

func initPC(c command) error {
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	if !c.AllIfaces {
		// Loopback only by default: deterministic and fast on CI hosts.
		se.SetInterfaceFilter(func(name string) bool { return name == "lo0" || name == "lo" })
	}
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return err
	}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se), webrtc.WithMediaEngine(m))
	var err error
	pc, err = api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return err
	}
	pc.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			emit(map[string]any{"event": "local_candidate", "candidate": "", "mid": "0"})
			return
		}
		init := cand.ToJSON()
		mid := ""
		if init.SDPMid != nil {
			mid = *init.SDPMid
		}
		emit(map[string]any{"event": "local_candidate", "candidate": init.Candidate, "mid": mid})
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		emit(map[string]any{"event": "ice_state", "state": s.String()})
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		emit(map[string]any{"event": "connection_state", "state": s.String()})
	})
	pc.OnSignalingStateChange(func(s webrtc.SignalingState) {
		emit(map[string]any{"event": "signaling_state", "state": s.String()})
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) { watchChannel(dc) })
	pc.OnTrack(onTrack)
	for _, kind := range c.Media {
		var cap webrtc.RTPCodecCapability
		switch kind {
		case "audio":
			cap = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}
		case "video":
			cap = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}
		default:
			return fmt.Errorf("unknown media %q", kind)
		}
		t, err := webrtc.NewTrackLocalStaticRTP(cap, kind, "pion")
		if err != nil {
			return err
		}
		if _, err := pc.AddTrack(t); err != nil {
			return err
		}
		tracks[kind] = t
	}
	for _, spec := range c.Channels {
		if err := createChannel(spec); err != nil {
			return err
		}
	}
	return nil
}

func createChannel(spec channelSpec) error {
	init := &webrtc.DataChannelInit{
		Ordered:           spec.Ordered,
		MaxRetransmits:    spec.MaxRetransmits,
		MaxPacketLifeTime: spec.MaxPacketLifeTime,
		Protocol:          &spec.Protocol,
	}
	if spec.Negotiated {
		n := true
		init.Negotiated = &n
		init.ID = spec.ID
	}
	dc, err := pc.CreateDataChannel(spec.Label, init)
	if err != nil {
		return err
	}
	watchChannel(dc)
	return nil
}

func watchChannel(dc *webrtc.DataChannel) {
	chMu.Lock()
	channels[dc.Label()] = dc
	chMu.Unlock()
	dc.OnOpen(func() {
		id := -1
		if dc.ID() != nil {
			id = int(*dc.ID())
		}
		emit(map[string]any{"event": "channel_open", "label": dc.Label(), "id": id,
			"protocol": dc.Protocol(), "ordered": dc.Ordered()})
	})
	dc.OnClose(func() {
		emit(map[string]any{"event": "channel_close", "label": dc.Label()})
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if msg.IsString {
			emit(map[string]any{"event": "message", "label": dc.Label(), "data": string(msg.Data), "binary": false})
			if err := dc.SendText("echo:" + string(msg.Data)); err != nil {
				fail(err)
			}
			return
		}
		emit(map[string]any{"event": "message", "label": dc.Label(),
			"data": base64.StdEncoding.EncodeToString(msg.Data), "binary": true})
		if err := dc.Send(append([]byte("echo"), msg.Data...)); err != nil {
			fail(err)
		}
	})
}

func onTrack(remote *webrtc.TrackRemote, recv *webrtc.RTPReceiver) {
	kind := remote.Kind().String()
	emit(map[string]any{"event": "track", "kind": kind, "ssrc": uint32(remote.SSRC()),
		"codec": remote.Codec().MimeType})
	local := tracks[kind]
	count, bytes := 0, 0
	for {
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			return
		}
		count++
		bytes += len(pkt.Payload)
		if count == 1 || count%50 == 0 {
			emit(map[string]any{"event": "rtp", "kind": kind, "count": count, "bytes": bytes})
		}
		if local != nil {
			echo := &rtp.Packet{Header: rtp.Header{Marker: pkt.Marker, Timestamp: pkt.Timestamp,
				SequenceNumber: pkt.SequenceNumber}, Payload: pkt.Payload}
			if err := local.WriteRTP(echo); err != nil {
				fail(err)
			}
		}
	}
}
