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
      // Simulcast: three layers of a 1280x720 camera (RFC 8853), sent
      // only, with bitrates that fit the initial bandwidth estimate.
      const video = !media.includes('video') ? false
        : c.simulcast ? { width: 1280, height: 720 } : true;
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: media.includes('audio'), video });
      for (const t of stream.getTracks()) {
        if (t.kind === 'video' && c.simulcast) {
          pc.addTransceiver(t, { direction: 'sendonly', streams: [stream], sendEncodings: [
            { rid: 'q', scaleResolutionDownBy: 4, maxBitrate: 40000 },
            { rid: 'h', scaleResolutionDownBy: 2, maxBitrate: 80000 },
            { rid: 'f', scaleResolutionDownBy: 1, maxBitrate: 150000 },
          ] });
        } else {
          pc.addTrack(t, stream);
        }
      }
    }
    for (const spec of c.channels || []) window.makeChannel(spec);
  };
};

// Playwright drives its own builds of Chromium, Firefox and WebKit.
async function openPlaywright() {
  const browser = await pw[kind].launch({ headless: true, ...launchOpts[kind] });
  const context = await browser.newContext();
  if (kind === 'chromium' && !mdns) await context.grantPermissions(['camera', 'microphone']);
  const page = await context.newPage();
  // A localhost origin is a secure context, required for getUserMedia.
  await page.route('http://localhost/**', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>peer</title>' }));
  return { page, url: 'http://localhost/', version: browser.version(), close: () => browser.close() };
}

// The installed Firefox (kind 'firefox-system'), driven over WebDriver
// BiDi with puppeteer-core. On macOS it is started through launchd
// (`open`): a Firefox started as a child of a terminal inherits the
// terminal's privacy restrictions and cannot read its own profile.
async function openSystemFirefox() {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const http = require('http');
  const { spawn, execFileSync } = require('child_process');
  const puppeteer = require('puppeteer-core');
  const bin = process.env.WEBRTC_FIREFOX || (process.platform === 'darwin'
    ? '/Applications/Firefox.app' : 'firefox');
  const base = process.platform === 'darwin' ? path.join(os.homedir(), 'Library', 'Caches') : os.tmpdir();
  const profile = fs.mkdtempSync(path.join(base, 'erlang-webrtc-ff-'));
  fs.writeFileSync(path.join(profile, 'user.js'), [
    'media.navigator.streams.fake', 'media.navigator.permission.disabled',
    'media.peerconnection.ice.loopback'].map((k) => `user_pref("${k}", true);`).join('\n') +
    '\nuser_pref("media.peerconnection.ice.obfuscate_host_addresses", false);\n');
  const port = 20000 + Math.floor(Math.random() * 20000);
  const args = ['--headless', '--no-remote', '--profile', profile, '--remote-debugging-port', String(port)];
  let child = null;
  if (process.platform === 'darwin' && bin.endsWith('.app')) {
    execFileSync('open', ['-n', '-a', bin, '--args', ...args]);
  } else {
    child = spawn(bin, args, { stdio: 'ignore' });
  }
  const server = http.createServer((_, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><title>peer</title>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  let browser;
  for (let i = 0; i < 100 && !browser; i++) {
    try {
      browser = await puppeteer.connect({ browserWSEndpoint: `ws://127.0.0.1:${port}/session`, protocol: 'webDriverBiDi' });
    } catch (e) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  if (!browser) throw new Error('system firefox did not start');
  const page = await browser.newPage();
  const close = async () => {
    try { await browser.close(); } catch (e) { /* already gone */ }
    if (child) child.kill();
    else try { execFileSync('pkill', ['-f', profile]); } catch (e) { /* exited */ }
    server.close();
    fs.rmSync(profile, { recursive: true, force: true });
  };
  return { page, url: `http://localhost:${server.address().port}/`, version: await browser.version(), close };
}

async function main() {
  const b = kind === 'firefox-system' ? await openSystemFirefox() : await openPlaywright();
  const browser = { close: b.close };
  const page = b.page;
  page.on('console', (m) => process.stderr.write(`[page] ${m.text()}\n`));
  await page.exposeFunction('emit', (ev) => emit(ev));
  await page.goto(b.url);
  await page.evaluate(pageScript);
  emit({ event: 'ready', implementation: mdns ? kind + '-mdns' : kind, version: b.version });

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
