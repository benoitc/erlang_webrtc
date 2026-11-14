// Browser peer adapter for the erlang_webrtc interop suite.
//
// Usage: node peer.js chromium|firefox|webkit [--mdns]
//
// --mdns (Chromium only) keeps Chromium's default of hiding host
// addresses behind <uuid>.local mDNS names
// (draft-ietf-mmusic-mdns-ice-candidates) and does not grant media
// permissions, which would make Chromium expose the addresses.
//
// Speaks the line-delimited JSON protocol of ../PROTOCOL.md on stdio and
// drives a real RTCPeerConnection inside a headless browser page.
// Browsers decode media, so like the aiortc adapter the page sends media
// from fake capture devices and reports decoded frames; the Erlang side
// echoes the RTP it receives.
'use strict';

const readline = require('readline');
const pw = require('playwright');

const kind = process.argv[2] || 'chromium';
const mdns = process.argv.includes('--mdns');

function emit(ev) {
  process.stdout.write(JSON.stringify(ev) + '\n');
}

const launchOpts = {
  chromium: {
    args: [
      '--use-fake-device-for-media-stream',
      '--use-fake-ui-for-media-stream',
      '--allow-loopback-in-peer-connection',
      ...(mdns ? [] : ['--disable-features=WebRtcHideLocalIpsWithMdns']),
    ],
  },
  firefox: {
    firefoxUserPrefs: {
      'media.navigator.streams.fake': true,
      'media.navigator.permission.disabled': true,
      'media.peerconnection.ice.loopback': true,
      'media.peerconnection.ice.obfuscate_host_addresses': false,
    },
  },
  webkit: {},
};

// Runs inside the page.
const pageScript = () => {
  window.channels = {};
  window.watch = (dc) => {
    window.channels[dc.label] = dc;
    dc.binaryType = 'arraybuffer';
    const opened = () => window.emit({ event: 'channel_open', label: dc.label, id: dc.id,
                                       protocol: dc.protocol, ordered: dc.ordered });
    if (dc.readyState === 'open') opened(); else dc.onopen = opened;
    dc.onclose = () => window.emit({ event: 'channel_close', label: dc.label });
    dc.onmessage = (m) => {
      if (typeof m.data === 'string') {
        window.emit({ event: 'message', label: dc.label, data: m.data, binary: false });
        dc.send('echo:' + m.data);
      } else {
        const bytes = new Uint8Array(m.data);
        let s = '';
        for (const b of bytes) s += String.fromCharCode(b);
        window.emit({ event: 'message', label: dc.label, data: btoa(s), binary: true });
        const out = new Uint8Array(bytes.length + 4);
        out.set([101, 99, 104, 111]);
        out.set(bytes, 4);
        dc.send(out);
      }
    };
  };
  window.makeChannel = (spec) => {
    const init = {};
    if (spec.ordered !== undefined && spec.ordered !== null) init.ordered = spec.ordered;
    if (spec.max_retransmits != null) init.maxRetransmits = spec.max_retransmits;
    if (spec.max_packet_life_time != null) init.maxPacketLifeTime = spec.max_packet_life_time;
    if (spec.negotiated) { init.negotiated = true; init.id = spec.id; }
    if (spec.protocol) init.protocol = spec.protocol;
    window.watch(window.pc.createDataChannel(spec.label, init));
  };
  window.init = async (c) => {
    const pc = new RTCPeerConnection({ bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require' });
    window.pc = pc;
    pc.onicecandidate = (e) => window.emit({ event: 'local_candidate',
      candidate: e.candidate ? e.candidate.candidate : '',
      mid: e.candidate ? e.candidate.sdpMid : '0' });
    pc.oniceconnectionstatechange = () => window.emit({ event: 'ice_state', state: pc.iceConnectionState });
    pc.onconnectionstatechange = () => window.emit({ event: 'connection_state', state: pc.connectionState });
    pc.onsignalingstatechange = () => window.emit({ event: 'signaling_state', state: pc.signalingState });
    pc.ondatachannel = (e) => window.watch(e.channel);
    pc.ontrack = (e) => {
      window.emit({ event: 'track', kind: e.track.kind, mid: e.transceiver.mid, ssrc: 0, codec: '' });
    };
    // Report decoded video frames and received audio packets.
    const last = {};
    window.poll = setInterval(async () => {
      try {
        const stats = await pc.getStats();
        stats.forEach((s) => {
          if (s.type !== 'inbound-rtp') return;
          const n = s.kind === 'video' ? (s.framesDecoded || 0) : (s.packetsReceived || 0);
          if (n > 0 && n !== last[s.kind]) {
            last[s.kind] = n;
            window.emit({ event: 'rtp', kind: s.kind, count: n, bytes: s.bytesReceived || 0 });
          }
        });
      } catch (err) {
        console.log('stats: ' + err);
      }
    }, 250);
    const media = c.media || [];
    if (media.length) {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: media.includes('audio'), video: media.includes('video') });
      for (const t of stream.getTracks()) pc.addTrack(t, stream);
    }
    for (const spec of c.channels || []) window.makeChannel(spec);
  };
};

async function main() {
  const browser = await pw[kind].launch({ headless: true, ...launchOpts[kind] });
  const context = await browser.newContext();
  if (kind === 'chromium' && !mdns) await context.grantPermissions(['camera', 'microphone']);
  const page = await context.newPage();
  page.on('console', (m) => process.stderr.write(`[page] ${m.text()}\n`));
  await page.exposeFunction('emit', (ev) => emit(ev));
  // A localhost origin is a secure context, required for getUserMedia.
  await page.route('http://localhost/**', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>peer</title>' }));
  await page.goto('http://localhost/');
  await page.evaluate(pageScript);
  emit({ event: 'ready', implementation: mdns ? kind + '-mdns' : kind, version: browser.version() });

  const handlers = {
    init: (c) => page.evaluate((c) => window.init(c), c),
    create_offer: (c) => page.evaluate(async (c) => {
      const o = await window.pc.createOffer({ iceRestart: !!c.ice_restart });
      await window.pc.setLocalDescription(o);
      window.emit({ event: 'local_description', type: 'offer', sdp: window.pc.localDescription.sdp });
    }, c),
    remote_description: (c) => page.evaluate(async (c) => {
      await window.pc.setRemoteDescription({ type: c.type, sdp: c.sdp });
      if (c.type === 'offer') {
        await window.pc.setLocalDescription(await window.pc.createAnswer());
        window.emit({ event: 'local_description', type: 'answer', sdp: window.pc.localDescription.sdp });
      }
    }, c),
    remote_candidate: (c) => page.evaluate(async (c) => {
      await window.pc.addIceCandidate(c.candidate ? { candidate: c.candidate, sdpMid: c.mid } : null);
    }, c),
    send: (c) => page.evaluate((c) => {
      const dc = window.channels[c.label];
      if (c.binary) dc.send(Uint8Array.from(atob(c.data), (ch) => ch.charCodeAt(0)));
      else dc.send(c.data);
    }, c),
    create_channel: (c) => page.evaluate((c) => window.makeChannel(c), c),
    close_channel: (c) => page.evaluate((c) => window.channels[c.label].close(), c),
    stats: () => page.evaluate(async () => {
      const r = await window.pc.getStats();
      const out = {};
      r.forEach((s) => { out[s.id] = s; });
      window.emit({ event: 'stats', stats: out });
    }),
    close: async () => {
      await page.evaluate(() => window.pc && window.pc.close());
      await browser.close();
      process.exit(0);
    },
  };

  // Commands run one at a time, in order.
  let chain = Promise.resolve();
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    chain = chain.then(async () => {
      let c;
      try {
        c = JSON.parse(line);
        const h = handlers[c.cmd];
        if (!h) throw new Error('unknown command ' + c.cmd);
        await h(c);
      } catch (e) {
        emit({ event: 'error', message: `${c ? c.cmd : '?'}: ${e.message}` });
      }
    });
  });
  rl.on('close', async () => { await browser.close(); process.exit(0); });
}

main().catch((e) => {
  emit({ event: 'error', message: e.message });
  // Do not wait for a browser that failed to launch.
  setTimeout(() => process.exit(1), 100);
});
