// CROCbox gateway helper. Runs under the bundled Node 24 (not Electron).
// Connects to the local OpenClaw gateway through OpenClaw's official
// GatewayClient (package export ./plugin-sdk/gateway-runtime), which performs
// protocol v4 device-auth signing. Prints exactly one JSON line, then exits.
// Usage: node gateway-helper.mjs <hello|catalog|invoke>  (invoke: CROCBOX_INVOKE_TOOL, CROCBOX_INVOKE_ARGS)
// Env: CROCBOX_OPENCLAW_DIR, CROCBOX_GATEWAY_URL, CROCBOX_GATEWAY_TOKEN, CROCBOX_VERSION
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const action = process.argv[2] || 'catalog';
const ocDir = process.env.CROCBOX_OPENCLAW_DIR || '';
const url = process.env.CROCBOX_GATEWAY_URL || 'ws://127.0.0.1:18789';
const token = process.env.CROCBOX_GATEWAY_TOKEN || '';
const TIMEOUT_MS = Number(process.env.CROCBOX_HELPER_TIMEOUT_MS) || 20000;

let done = false;
let client = null;
function errText(err) { return String((err && err.message) || err); }
function authSummary(hello) {
  const a = (hello && hello.auth) || {};
  return { role: a.role, scopes: a.scopes };
}
function finish(result, code) {
  if (done) return;
  done = true;
  process.stdout.write(JSON.stringify(result) + '\n');
  const exit = () => process.exit(code);
  if (client) { client.stopAndWait({ timeoutMs: 1000 }).then(exit, exit); } else { exit(); }
}
setTimeout(() => finish({ ok: false, stage: 'timeout', error: 'no result within ' + TIMEOUT_MS + ' ms' }, 2), TIMEOUT_MS);

async function main() {
  if (ocDir === '') throw new Error('CROCBOX_OPENCLAW_DIR not set');
  const pkg = JSON.parse(fs.readFileSync(path.join(ocDir, 'package.json'), 'utf8'));
  const exp = pkg.exports && pkg.exports['./plugin-sdk/gateway-runtime'];
  const rel = typeof exp === 'string' ? exp : (exp && (exp.default || exp.import));
  if (typeof rel !== 'string') throw new Error('export ./plugin-sdk/gateway-runtime not found');
  const sdk = await import(pathToFileURL(path.join(ocDir, rel)).href);
  client = new sdk.GatewayClient({
    url,
    token,
    clientName: 'openclaw-macos',
    clientDisplayName: 'CROCbox',
    clientVersion: process.env.CROCBOX_VERSION || '0.0.0',
    platform: 'darwin',
    mode: 'ui',
    role: 'operator',
    scopes: action === 'invoke' ? ['operator.read', 'operator.write'] : ['operator.read'],
    onHelloOk: async (hello) => {
      try {
        if (action === 'hello') {
          finish({ ok: true, stage: 'hello', protocol: hello.protocol, server: hello.server, auth: authSummary(hello) }, 0);
          return;
        }
        if (action === 'invoke') {
          const name = process.env.CROCBOX_INVOKE_TOOL || '';
          const args = JSON.parse(process.env.CROCBOX_INVOKE_ARGS || '{}');
          const result = await client.request('tools.invoke', { name, args });
          finish({ ok: true, stage: 'invoke', protocol: hello.protocol, auth: authSummary(hello), result }, 0);
          return;
        }
        const catalog = await client.request('tools.catalog', {});
        finish({ ok: true, stage: 'catalog', protocol: hello.protocol, server: hello.server, auth: authSummary(hello), catalog }, 0);
      } catch (err) {
        finish({ ok: false, stage: 'request', error: errText(err) }, 1);
      }
    },
    onConnectError: (err) => finish({ ok: false, stage: 'connect', error: errText(err) }, 1),
    onReconnectPaused: (info) => finish({ ok: false, stage: 'paused', error: info }, 1),
  });
  client.start();
}
main().catch((err) => finish({ ok: false, stage: 'setup', error: errText(err) }, 1));
