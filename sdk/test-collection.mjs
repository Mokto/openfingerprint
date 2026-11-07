import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium, firefox, webkit } = require('playwright-core');
const source = await readFile(new URL('./dist/index.iife.js', import.meta.url), 'utf8');
const requests = [];
const eventId = 'a'.repeat(64);
const challenge = 'b'.repeat(64);
const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    if (request.url === '/sdk.js') {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(source);
    } else if (request.url === '/') {
        response.setHeader('Content-Type', 'text/html');
        response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-src 'self'");
        response.end('<!doctype html><html><body><script src="/sdk.js"></script></body></html>');
    } else {
        let body = '';
        for await (const chunk of request) body += chunk;
        requests.push({ path: request.url, headers: request.headers, body: body ? JSON.parse(body) : null });
        response.setHeader('Content-Type', 'application/json');
        if (request.url === '/redirect') {
            response.writeHead(302, { Location: '/redirect-target' });
            response.end();
        } else if (request.url === '/invalid') {
            response.end(JSON.stringify({ event_id: eventId, automation: false }));
        } else if (request.url === '/failure') {
            response.writeHead(503);
            response.end('{}');
        } else if (request.url === '/slow') {
            setTimeout(() => response.end(JSON.stringify({ event_id: eventId })), 500);
        } else response.end(JSON.stringify({ event_id: eventId }));
    }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
let phase = 'startup';
try {
    for (const [name, engine] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
        const browser = await engine.launch();
        try {
            const page = await browser.newPage();
            await page.goto(origin);
            phase = `${name}: automatic evidence submission`;
            const before = requests.length;
            assert.deepEqual(await page.evaluate(challenge => OpenFingerprint.identify({
                endpoint: '/collect', challenge, timeoutMs: 1000
            }), challenge), { eventId });
            assert.equal(requests.length, before + 1);
            const request = requests.at(-1);
            assert.deepEqual(Object.keys(request.body).sort(), ['challenge', 'context', 'signals']);
            assert.equal(request.body.challenge, challenge);
            assert.equal(request.body.signals.automation.version, 2);
            assert.equal(request.body.context.userAgent, request.headers['user-agent']);
            assert.equal(request.body.context.platform, await page.evaluate(() => navigator.platform));
            assert.equal(request.body.context.webrtc, undefined);
            assert.equal(request.headers.origin, origin);
            assert.equal(request.headers.cookie, undefined);
            assert.equal(request.headers.authorization, undefined);
            assert.equal(request.headers.referer, undefined);
            assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
            phase = `${name}: endpoint and option validation before network access`;
            for (const options of [
                { endpoint: 'https://other.example/collect' },
                { endpoint: 'http://other.example/collect' },
                { endpoint: '/collect?secret=x' },
                { endpoint: '/collect#hash' },
                { endpoint: '' },
                { challenge: 'wrong' },
                { networkTimeoutMs: 0 },
                { networkTimeoutMs: 30001 },
                { webrtcStun: 'http://stun.example' },
                { webrtcStun: 'stun:host/path' },
                { webrtcStun: 42 }
            ]) {
                const count = requests.length;
                assert.equal(await page.evaluate(async args => {
                    try { await OpenFingerprint.identify(args); return false; } catch { return true; }
                }, { endpoint: '/collect', challenge, ...options }), true);
                assert.equal(requests.length, count);
            }
            phase = `${name}: opt-in WebRTC addresses`;
            const rtc = await browser.newPage();
            await rtc.addInitScript(() => {
                window.RTCPeerConnection = class {
                    constructor(config) { window.iceConfig = config; }
                    createDataChannel() {}
                    async createOffer() { return {}; }
                    async setLocalDescription() {
                        const lines = [
                            'candidate:1 1 udp 1677729535 203.0.113.5 46342 typ srflx raddr 0.0.0.0 rport 0',
                            'candidate:2 1 udp 2122260223 192.168.1.20 50000 typ host',
                            'candidate:3 1 udp 2122260223 4f0d1a2b-0000-4000-8000-000000000000.local 50001 typ host',
                            'candidate:4 1 udp 2122194687 2001:db8::5 50002 typ host',
                            'candidate:5 1 udp 41885439 198.51.100.7 3478 typ relay',
                            'candidate:6 1 udp 1677729535 203.0.113.5 46343 typ srflx'
                        ];
                        setTimeout(() => {
                            for (const candidate of lines) this.onicecandidate({ candidate: { candidate } });
                            this.onicecandidate({ candidate: null });
                        });
                    }
                    close() { window.rtcClosed = true; }
                };
            });
            await rtc.goto(origin);
            await rtc.evaluate(challenge => OpenFingerprint.identify({
                endpoint: '/collect', challenge, timeoutMs: 1000, webrtcStun: 'stun:stun.example.test:3478'
            }), challenge);
            assert.deepEqual(requests.at(-1).body.context.webrtc, { addresses: ['203.0.113.5', '2001:db8::5'] });
            assert.deepEqual(await rtc.evaluate(() => [window.iceConfig, window.rtcClosed]), [{ iceServers: [{ urls: 'stun:stun.example.test:3478' }] }, true]);
            const unsupported = await browser.newPage();
            await unsupported.addInitScript(() => { window.RTCPeerConnection = class { constructor() { throw new Error('blocked'); } }; });
            await unsupported.goto(origin);
            await unsupported.evaluate(challenge => OpenFingerprint.identify({
                endpoint: '/collect', challenge, timeoutMs: 1000, webrtcStun: 'stun:stun.example.test:3478'
            }), challenge);
            assert.equal(requests.at(-1).body.context.webrtc, undefined);
            phase = `${name}: no redirects, retries or unauthenticated verdicts`;
            for (const endpoint of ['/redirect', '/invalid', '/failure', '/slow']) {
                const count = requests.length;
                assert.equal(await page.evaluate(async args => {
                    try { await OpenFingerprint.identify(args); return false; } catch { return true; }
                }, { endpoint, challenge, timeoutMs: 500, networkTimeoutMs: endpoint === '/slow' ? 50 : 5000 }), true);
                assert.equal(requests.length, count + 1);
                assert.equal(requests.at(-1).path, endpoint);
            }
            console.log(`${name}: automatic automation submission, same-origin transport, opaque results and failure handling passed`);
        } finally {
            await browser.close();
        }
    }
} catch {
    console.error(`SDK collection self-check failed during: ${phase}. Sensitive values suppressed.`);
    process.exitCode = 1;
} finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
}
