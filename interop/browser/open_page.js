// Open a page in a headless Playwright browser and wait for a console
// line: `node open_page.js chromium|firefox URL TEXT`. Prints the page's
// console lines; exits 0 once one contains TEXT, 1 after 20 s.
const pw = require('playwright');
const [kind, url, expect] = process.argv.slice(2);

const launchOpts = {
  // Host addresses as they are, not mDNS names (multicast is not
  // needed to resolve them).
  chromium: { args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] },
  firefox: { firefoxUserPrefs: { 'media.peerconnection.ice.obfuscate_host_addresses': false } },
};

(async () => {
  const browser = await pw[kind].launch({ headless: true, ...launchOpts[kind] });
  const page = await browser.newPage();
  const done = new Promise((resolve) => {
    page.on('console', (m) => {
      process.stdout.write(m.text() + '\n');
      if (m.text().includes(expect)) resolve(0);
    });
    page.on('pageerror', (e) => process.stdout.write('error: ' + e.message + '\n'));
  });
  await page.goto(url, { waitUntil: 'commit' });
  const code = await Promise.race([done, new Promise((r) => setTimeout(() => r(1), 20000))]);
  await browser.close();
  process.exit(code);
})().catch((e) => { process.stdout.write('error: ' + e.message + '\n'); process.exit(1); });
