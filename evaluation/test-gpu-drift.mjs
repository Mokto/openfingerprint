import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../sdk/package.json', import.meta.url));
const { chromium, firefox, webkit } = require('playwright-core');
const sdk = await readFile(new URL('../sdk/dist/index.js', import.meta.url));
const { version: sdkVersion } = JSON.parse(await readFile(new URL('../sdk/package.json', import.meta.url)));
const components = ['audio', 'canvas', 'fontFallbacks', 'fontPreferences', 'fonts', 'gpu'];
const hints = ['architecture', 'browser', 'display', 'features', 'hardware', 'locale', 'math', 'media', 'platform', 'screen'];
const probes = [...components, ...hints];
const complete = row => row?.version === 1 && row.excluded.length === 0
    && /^[a-f0-9]{64}$/.test(row.fingerprint ?? '')
    && Object.keys(row.components).length === components.length && Object.keys(row.hints).length === hints.length
    && probes.every(name => !row.unavailable?.[name] && /^[a-f0-9]{64}$/.test(row.components[name] ?? row.hints[name] ?? ''));
const matches = (a, b) => complete(a) && complete(b) && probes.filter(name => name !== 'gpu').every(name => (a.components[name] ?? a.hints[name]) === (b.components[name] ?? b.hints[name]));
const fixture = { version: 1, fingerprint: 'd'.repeat(64), excluded: [], components: Object.fromEntries(components.map(name => [name, 'a'.repeat(64)])), hints: Object.fromEntries(hints.map(name => [name, 'a'.repeat(64)])) };
const changed = structuredClone(fixture);
changed.components.gpu = 'b'.repeat(64);
assert(matches(fixture, changed));
for (const name of probes.filter(name => name !== 'gpu')) {
    const other = structuredClone(changed);
    (components.includes(name) ? other.components : other.hints)[name] = 'c'.repeat(64);
    assert(!matches(fixture, other));
}
delete changed.components.gpu;
assert(!matches(fixture, changed));
assert(!matches(fixture, { ...fixture, excluded: ['audio', 'canvas', 'screen'] }));
assert(!matches(fixture, { ...fixture, version: 2 }));
assert(!matches(fixture, { ...fixture, fingerprint: null }));
assert(!matches(fixture, { ...fixture, unavailable: { gpu: 'timeout' } }));

const server = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', request.url === '/sdk.js' ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8');
    if (request.url === '/sdk.js') response.end(sdk);
    else if (request.url === '/') response.end('<!doctype html><meta charset="utf-8"><title>GPU drift lab</title>');
    else response.writeHead(404).end();
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const report = { sdkVersion, build: createHash('sha256').update(sdk).digest('hex'), cohort: 'synthetic', physicalHosts: 1, independentDifferentDevicePairs: 0, falseMergeRate: null, externalRequests: 0, cases: [] };
let faultInjected = false;
try {
    for (const [engineName, engine] of Object.entries({ chromium, firefox, webkit })) {
        const cases = [
            { condition: 'baseline' },
            { condition: 'fresh-process', instrument: true },
            { condition: 'context-loss', instrument: true, loss: true }
        ];
        if (engineName === 'chromium') {
            cases.push({ condition: 'swiftshader', instrument: true, args: ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
            if (process.platform === 'darwin') cases.push({ condition: 'metal', instrument: true, args: ['--use-gl=angle', '--use-angle=metal', '--enable-gpu', '--ignore-gpu-blocklist'] });
            cases.push({ condition: 'cpu-6x', instrument: true, cpu: 6 });
        }
        let baseline;
        for (const scenario of cases) {
            const browser = await engine.launch({ headless: true, args: scenario.args, timeout: 15000 });
            const rows = [];
            try {
                const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US', timezoneId: 'Europe/Copenhagen', deviceScaleFactor: 1 });
                await context.route('**/*', route => {
                    if (new URL(route.request().url()).origin !== origin) { report.externalRequests++; return route.abort(); }
                    return route.continue();
                });
                if (scenario.instrument) await context.addInitScript(({ loss }) => {
                    const stats = window.gpuLab = { contexts: 0, nullReads: 0, lostOnRead: false, faultInjected: false };
                    const original = HTMLCanvasElement.prototype.getContext;
                    HTMLCanvasElement.prototype.getContext = function (type, ...args) {
                        const ctx = original.call(this, type, ...args);
                        if (type !== 'webgl' || !ctx) return ctx;
                        stats.contexts++;
                        if (loss) {
                            const extension = ctx.getExtension('WEBGL_lose_context');
                            if (extension) { extension.loseContext(); stats.faultInjected = true; }
                        }
                        for (const name of ['getParameter', 'getShaderPrecisionFormat', 'getSupportedExtensions']) {
                            const read = ctx[name].bind(ctx);
                            ctx[name] = (...parameters) => {
                                stats.lostOnRead ||= ctx.isContextLost();
                                const value = read(...parameters);
                                if (value === null) stats.nullReads++;
                                return value;
                            };
                        }
                        return ctx;
                    };
                }, { loss: scenario.loss === true });
                const page = await context.newPage();
                if (scenario.cpu) await (await context.newCDPSession(page)).send('Emulation.setCPUThrottlingRate', { rate: scenario.cpu });
                for (let attempt = 0; attempt < 3; attempt++) {
                    await page.goto(origin);
                    const row = await page.evaluate(async () => {
                        try {
                            const { collect } = await import('/sdk.js');
                            const evidence = await collect();
                            return { ...evidence, readHealth: window.gpuLab ?? null };
                        } catch { return null; }
                    });
                    rows.push(row);
                    if (scenario.condition === 'baseline' && attempt === 0) baseline = row;
                }
                assert(rows.every(row => row === null || row.version === 1), 'Unsupported SDK result schema.');
                const comparable = rows.filter(row => row !== baseline && complete(row) && complete(baseline));
                const changedProbes = Object.fromEntries(probes.map(name => [name, comparable.filter(row => (row.components[name] ?? row.hints[name]) !== (baseline.components[name] ?? baseline.hints[name])).length]).filter(([, count]) => count));
                const lost = rows.filter(row => row?.readHealth?.lostOnRead);
                faultInjected ||= rows.some(row => row?.readHealth?.faultInjected);
                report.cases.push({
                    engine: engineName, version: browser.version(), condition: scenario.condition, attempts: rows.length,
                    collected: rows.filter(Boolean).length, fullFingerprints: rows.filter(row => row?.fingerprint).length,
                    gpuEligible: rows.filter(complete).length, comparableWithFixedFirstBaseline: comparable.length,
                    distinctGpuHashes: new Set(rows.map(row => row?.components.gpu).filter(Boolean)).size,
                    softwareRendererReports: rows.filter(row => row?.automation?.softwareRenderer === true).length,
                    faultInjectedAttempts: rows.filter(row => row?.readHealth?.faultInjected).length,
                    lostContextReads: lost.length, nullGpuReadAttempts: rows.filter(row => row?.readHealth?.nullReads > 0).length,
                    lostContextStillHasGpu: lost.filter(row => row.components.gpu).length,
                    lostContextStillHasFullFingerprint: lost.filter(row => row.fingerprint).length,
                    gpuOnlyChangesFromBaseline: comparable.filter(row => matches(baseline, row) && row.components.gpu !== baseline.components.gpu).length,
                    changedProbes
                });
            } finally { await browser.close(); }
            console.log(`${engineName}: ${scenario.condition} completed.`);
        }
    }
    assert.equal(report.externalRequests, 0);
    assert(faultInjected, 'No native context loss was injected; this is not a completed GPU fault check.');
    const output = new URL('../.test-results/identification/', import.meta.url);
    await mkdir(output, { recursive: true });
    await writeFile(new URL('gpu-drift.json', output), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    console.log(JSON.stringify(report, null, 2));
} finally { await new Promise(resolve => server.close(resolve)); }
