import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';
import { gunzipSync } from 'node:zlib';

const root = fileURLToPath(new URL('./', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const day = 86400;
const repo = 'tobilg/public-cloud-provider-ip-ranges';
const licenseHash = 'e8dbc5476e2bbab422e8c8fcfa61cb19dc4f5b3ff75a13f4458ad6deaf7dac7b';
const execute = promisify(execFile);
const binary = () => process.env.OPENFINGERPRINT_API_BINARY ?? resolve(root, 'target/debug/openfingerprint-api');
const epoch = text => {
    const ms = Date.parse(text);
    assert(Number.isFinite(ms) && new Date(ms).toISOString().replace('.000Z', 'Z') === text, 'Invalid source date');
    return ms / 1000;
};

export async function download(url, signal) {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(30000), signal].filter(Boolean)), headers: { Accept: 'application/vnd.github+json' } });
    if (response.status !== 200) { await response.body?.cancel(); throw new Error(`HTTP ${response.status}`); }
    let size = 0;
    const chunks = [];
    for await (const chunk of response.body) {
        size += chunk.length;
        assert(size <= 32 * 1024 * 1024, 'Source exceeds download limit');
        chunks.push(chunk);
    }
    return Buffer.concat(chunks);
}
function metadata(id, license, license_url, attribution, url, revision, updated, now, lifetime) {
    assert(Number.isSafeInteger(updated) && updated > 0 && updated <= now && now < updated + lifetime, 'Stale/future source');
    return { id, license, license_url, attribution, url, revision, updated_at_unix: updated, fetched_at_unix: now, expires_at_unix: updated + lifetime };
}
export async function tor(fetchBytes, now) {
    const base = 'https://collector.torproject.org/recent/exit-lists/';
    const index = String(await fetchBytes(base));
    const files = [...index.matchAll(/href="(\d{4}-\d\d-\d\d-\d\d-\d\d-\d\d)"/g)].map(m => m[1]).sort();
    assert(files.length > 0 && files.length < 1000, 'Invalid exit-list index');
    const name = files.at(-1);
    const [year, month, date, hour, minute, second] = name.split('-');
    const updated = epoch(`${year}-${month}-${date}T${hour}:${minute}:${second}Z`);
    const body = String(await fetchBytes(base + name));
    const entries = new Map();
    for (const line of body.split('\n')) {
        if (!line.startsWith('ExitAddress ')) continue;
        const match = /^ExitAddress (\S+) (\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)\r?$/.exec(line);
        assert(match && isIP(match[1]), 'Invalid observed exit address');
        const observed = epoch(`${match[2]}T${match[3]}Z`);
        assert(Number.isSafeInteger(observed) && observed <= now, 'Invalid exit observation date');
        if (observed > now - day) entries.set(match[1], Math.max(entries.get(match[1]) ?? 0, observed));
    }
    assert(entries.size > 0 && entries.size <= 100000, 'Invalid exit address count');
    return { metadata: metadata('tor_exit', 'CC0-1.0', 'https://creativecommons.org/publicdomain/zero/1.0/', 'The Tor Project, observed exit addresses', base + name, sha(body), updated, now, 3 * 3600), entries: [...entries.keys()].sort().map(ip => ({ ip, observed_at_unix: entries.get(ip) })) };
}
export async function hosting(fetchBytes, now) {
    const commits = JSON.parse(String(await fetchBytes(`https://api.github.com/repos/${repo}/commits?path=data/providers/all.json&per_page=1`)));
    const commit = commits[0];
    assert(/^[a-f0-9]{40}$/.test(commit?.sha), 'Invalid cloud source revision');
    const base = `https://raw.githubusercontent.com/${repo}/${commit.sha}/`;
    const license = String(await fetchBytes(base + 'LICENSE'));
    assert(sha(license) === licenseHash, 'Cloud source license changed: review required');
    const rows = JSON.parse(String(await fetchBytes(base + 'data/providers/all.json')));
    assert(Array.isArray(rows) && rows.length > 0 && rows.length <= 200000, 'Invalid cloud range count');
    const entries = [];
    const seen = new Set();
    for (const row of rows) {
        assert(typeof row.cloud_provider === 'string' && /^[A-Za-z0-9 _-]{1,64}$/.test(row.cloud_provider), 'Invalid cloud provider');
        assert(typeof row.cidr_block === 'string', 'Invalid cloud network');
        const [ip, prefix, extra] = row.cidr_block.split('/');
        const family = isIP(ip);
        assert(family && extra === undefined && /^\d{1,3}$/.test(prefix) && +prefix > 0 && +prefix <= (family === 4 ? 32 : 128), 'Invalid cloud CIDR');
        const key = `${row.cidr_block}|${row.cloud_provider}`;
        if (!seen.has(key)) entries.push({ network: row.cidr_block, provider: row.cloud_provider });
        seen.add(key);
    }
    return { metadata: { ...metadata('cloud_ranges', 'MIT', `https://github.com/${repo}/blob/${commit.sha}/LICENSE`, 'Tobi, public-cloud-provider-ip-ranges (derived published provider ranges)', `https://github.com/${repo}/blob/${commit.sha}/data/providers/all.json`, commit.sha, epoch(commit.commit.committer.date), now, 7 * day), license_text: license }, entries };
}
async function asn(fetchBytes, now, directory) {
    const date = new Date(now * 1000);
    let url, compressed, updated;
    for (let offset = 0; offset <= 1; offset++) {
        const month = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() - offset, 1));
        const label = month.toISOString().slice(0, 7);
        url = `https://download.db-ip.com/free/dbip-asn-lite-${label}.mmdb.gz`;
        try { compressed = await fetchBytes(url); updated = month.getTime() / 1000; break; }
        catch (error) { if (error.message !== 'HTTP 404' || offset) throw error; }
    }
    const bytes = gunzipSync(compressed, { maxOutputLength: 64 * 1024 * 1024 });
    const revision = sha(bytes);
    const source = metadata('dbip_asn', 'CC-BY-4.0', 'https://creativecommons.org/licenses/by/4.0/', 'IP Geolocation by DB-IP — https://db-ip.com/', url, revision, updated, now, 45 * day);
    // ponytail: immutable monthly ASN versions remain on disk; prune unreferenced versions if volume usage becomes material.
    await atomic(resolve(directory, `asn-${revision}.mmdb`), bytes);
    return source;
}
async function atomic(path, bytes) {
    const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
    try {
        const file = await open(temporary, 'wx', 0o644);
        try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
        await rename(temporary, path);
    } finally { await unlink(temporary).catch(() => {}); }
}
export async function validate(path, signal) {
    await execute(binary(), ['--validate-network-data', path], { timeout: 30000, maxBuffer: 65536, signal });
}
async function acquireLock(path, signal) {
    const child = spawn(binary(), ['--lock-network-data', path], { stdio: ['pipe', 'pipe', 'pipe'], signal });
    child.stdin.on('error', () => {});
    child.stderr.resume();
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { child.kill(); reject(new Error('Updater lock timeout')); }, 10000);
        let output = '';
        child.stdout.on('data', data => {
            output += data;
            if (output.includes('Network updater lock acquired.')) { clearTimeout(timer); resolve(); }
        });
        child.once('error', () => { clearTimeout(timer); reject(new Error('Updater lock unavailable')); });
        child.once('exit', () => { clearTimeout(timer); reject(new Error('Updater lock unavailable')); });
    });
    return child;
}
export async function update(output, { fetchBytes = download, now = Math.floor(Date.now() / 1000), check = validate, signal } = {}) {
    output = resolve(output);
    await mkdir(dirname(output), { recursive: true });
    const lockPath = output + '.lock';
    const lost = new AbortController();
    signal = AbortSignal.any([signal, lost.signal].filter(Boolean));
    const lock = await acquireLock(lockPath, signal);
    lock.once('exit', () => lost.abort());
    const temporary = output + `.${randomBytes(8).toString('hex')}.tmp`;
    try {
        let result = { version: 1 };
        try {
            const previous = await open(output, 'r');
            try {
                assert((await previous.stat()).size <= 16 * 1024 * 1024, 'Manifest exceeds size limit');
                result = JSON.parse(await previous.readFile({ encoding: 'utf8', signal }));
            } finally { await previous.close(); }
        } catch (error) { if (error.code !== 'ENOENT') throw error; }
        let baselineValid = false;
        try { await check(output, signal); baselineValid = true; } catch {}
        const failures = [];
        let refreshed = 0;
        for (const [id, load] of [['tor', tor], ['hosting', hosting], ['asn', (fetch, time) => asn(fetch, time, dirname(output))]]) {
            signal?.throwIfAborted();
            try {
                if (id === 'asn' && baselineValid && result.asn && result.asn.fetched_at_unix <= now && now - result.asn.fetched_at_unix < day && result.asn.expires_at_unix > now) continue;
                const value = await load(url => fetchBytes(url, signal), now);
                const candidate = { ...result, [id]: value };
                await atomic(temporary, JSON.stringify(candidate) + '\n');
                await check(temporary, signal);
                result = candidate;
                baselineValid = true;
                refreshed++;
            } catch {
                failures.push(id);
                console.warn(`Network source ${id} could not refresh; previous evidence keeps its original expiry.`);
            }
        }
        signal?.throwIfAborted();
        assert(refreshed > 0, 'No network sources refreshed');
        await atomic(temporary, JSON.stringify(result) + '\n');
        await check(temporary, signal);
        signal?.throwIfAborted();
        await rename(temporary, output);
        return { failures, sources: ['tor', 'hosting', 'asn'].filter(id => result[id]) };
    } finally {
        // Never unlink the lock file: another writer may already be locking the same inode.
        if (lock.exitCode === null && lock.signalCode === null) {
            const exited = new Promise(resolve => lock.once('exit', resolve));
            lock.stdin.end();
            await exited;
        }
        await unlink(temporary).catch(() => {});
    }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const { values } = parseArgs({ options: { output: { type: 'string' } } });
        assert(values.output, 'An --output path is required');
        const controller = new AbortController();
        process.once('SIGTERM', () => controller.abort());
        process.once('SIGINT', () => controller.abort());
        const result = await update(values.output, { signal: controller.signal });
        console.log(`Network snapshot published atomically; sources: ${result.sources.join(', ')}.`);
        if (result.failures.length) process.exitCode = 1;
    } catch {
        console.error('Network update failed; the previous manifest was preserved. Check source availability, validator, volume permissions and active writers.');
        process.exitCode = 1;
    }
}
