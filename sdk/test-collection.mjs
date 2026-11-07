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
            assert.equal(request.body.signals.automation.version, 1);
            assert.equal(request.body.context.userAgent, request.headers['user-agent']);
            assert.equal(request.body.context.platform, await page.evaluate(() => navigator.platform));
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
                { networkTimeoutMs: 30001 }
            ]) {
                const count = requests.length;
                assert.equal(await page.evaluate(async args => {
                    try { await OpenFingerprint.identify(args); return false; } catch { return true; }
                }, { endpoint: '/collect', challenge, ...options }), true);
                assert.equal(requests.length, count);
            }
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
