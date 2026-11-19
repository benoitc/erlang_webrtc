// Open pages in a headless Playwright browser and wait for a console
// line: `node open_page.js chromium|firefox URL [URL...] TEXT`. Each URL
// gets its own page, opened in the order given; the camera is a fake
// one. Prints the pages' console lines (prefixed with the page number
// when there are several); exits 0 once one contains TEXT, 1 after 30 s.
const pw = require('playwright');
const [kind, ...rest] = process.argv.slice(2);
const expect = rest.pop();
const urls = rest;

const launchOpts = {
  // Host addresses as they are, not mDNS names (multicast is not
  // needed to resolve them), and a fake camera allowed without asking.
  chromium: {
    args: ['--disable-features=WebRtcHideLocalIpsWithMdns',
           '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
  },
  firefox: {
    firefoxUserPrefs: {
      'media.peerconnection.ice.obfuscate_host_addresses': false,
      'media.navigator.streams.fake': true,
      'media.navigator.permission.disabled': true,
    },
  },
};

(async () => {
  const browser = await pw[kind].launch({ headless: true, ...launchOpts[kind] });
  let found;
  const done = new Promise((resolve) => { found = resolve; });
  for (const [i, url] of urls.entries()) {
    const page = await browser.newPage();
    const tag = urls.length > 1 ? `[${i + 1}] ` : '';
    page.on('console', (m) => {
      process.stdout.write(tag + m.text() + '\n');
      if (m.text().includes(expect)) found(0);
    });
    page.on('pageerror', (e) => process.stdout.write(tag + 'error: ' + e.message + '\n'));
    await page.goto(url, { waitUntil: 'commit' });
  }
  const code = await Promise.race([done, new Promise((r) => setTimeout(() => r(1), 30000))]);
  await browser.close();
  process.exit(code);
})().catch((e) => { process.stdout.write('error: ' + e.message + '\n'); process.exit(1); });
