import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { domainToASCII, fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const root = fileURLToPath(new URL('./', import.meta.url));
const limit = 8 * 1024 * 1024;
let phase = 'source metadata';
const sources = [
    { id: 'disposable_email_domains', repo: 'disposable-email-domains/disposable-email-domains', branch: 'main', path: 'disposable_email_blocklist.conf', category: 'disposable', license: 'CC0-1.0', licensePath: 'LICENSE.txt', licenseHash: '521b63b0ca6dde974084d728b652c80bd8a169c845b9c3c124f4583957b93d54' },
    { id: 'fakefilter_recent', repo: '7c/fakefilter', branch: 'main', path: 'json/data.json', category: 'disposable', license: 'BSD-3-Clause', licensePath: 'LICENSE.md', licenseHash: '25e04934f5510427abb55d007d942a58184b095a2e40618b0a4b76b69b3da59a' },
    { id: 'is_a_dev', repo: 'is-a-dev/register', branch: 'main', path: 'README.md', domain: 'is-a.dev', category: 'free_subdomain', license: 'MIT', licensePath: 'LICENSE', licenseHash: '2ffd9de047964b8cb6e526079da1dc6c8ffd3d1691faabb6433b4100e5e2790b' },
    { id: 'is_a_bot', repo: 'free-domains/is-a.bot', branch: 'main', path: 'README.md', domain: 'is-a.bot', category: 'free_subdomain', license: 'MIT', licensePath: 'LICENSE', licenseHash: '14979e0fc8469d414ea35d1c3e08ebdd3b336ac07e55c0d089413bdcaeb88046' },
    { id: 'matomo_referrer_spam', repo: 'matomo-org/referrer-spam-list', branch: 'master', path: 'spammers.txt', category: 'referrer_spam', license: 'LicenseRef-Public-Domain', licensePath: 'README.md', licenseHash: '6b509c9d22e2c323586c8b07c23f33c2edda65faf23e4db6c94a226a5a6cff2e' }
];

export function domains(text) {
    const lines = text.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
    assert(lines.every(s => !/[\\/:@?#%\s\u0000-\u001F\u007F]/u.test(s)), 'Expected bare source hostnames');
    const entries = lines.map(s => domainToASCII(s.toLowerCase()));
    assert(entries.length > 0 && entries.length <= 100000, 'Invalid domain count');
    for (const value of entries) {
        assert(value.length <= 253 && /^[a-z0-9.-]+$/.test(value) && value.includes('.'), 'Invalid domain entry');
        assert(value.split('.').every(s => s.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(s)), 'Invalid domain label');
        assert(/[a-z]/.test(value.split('.').at(-1)), 'Invalid domain suffix');
    }
    return [...new Set(entries)].sort();
}

export function monitoredDomains(text, now) {
    const feed = JSON.parse(text);
    assert(feed && typeof feed === 'object' && !Array.isArray(feed), 'Invalid monitored envelope');
    assert(feed.version === 1 && Number.isSafeInteger(feed.t) && feed.t >= now - 3 * 86400 && feed.t <= now + 300, 'Monitored feed is stale or invalid');
    assert(feed.domains && typeof feed.domains === 'object' && !Array.isArray(feed.domains), 'Invalid monitored domains');
    const entries = Object.entries(feed.domains);
    assert(domains(entries.map(([name]) => name).join('\n')).length === entries.length, 'Duplicate normalized monitored names');
    for (const [, entry] of entries) {
        assert(entry && typeof entry === 'object' && !Array.isArray(entry), 'Invalid monitored observation');
        assert(typeof entry.provider === 'string' && entry.provider.length > 0 && entry.provider.length <= 256, 'Invalid monitored provider');
        assert(Number.isSafeInteger(entry.firstseen) && entry.firstseen > 0 && Number.isSafeInteger(entry.lastseen) && entry.firstseen <= entry.lastseen && entry.lastseen <= feed.t + 300 && entry.lastseen <= now + 300, 'Invalid monitored observation time');
    }
    return domains(entries.filter(([, entry]) => entry.lastseen >= now - 14 * 86400).map(([name]) => name).join('\n'));
}

const hash = text => createHash('sha256').update(text).digest('hex');
export async function download(url) {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(20000), headers: { Accept: 'application/vnd.github+json' } });
    assert(response.status === 200, `Public source unavailable (HTTP ${response.status})`);
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > limit) { await reader.cancel(); throw new Error('Public source too large'); }
        chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
}

export async function snapshot(fetchText = download, now = Math.floor(Date.now() / 1000)) {
    const datasets = [];
    for (const source of sources) {
        phase = source.id;
        const commit = JSON.parse(await fetchText(`https://api.github.com/repos/${source.repo}/commits/${source.branch}`));
        assert(/^[a-f0-9]{40}$/.test(commit.sha), 'Invalid source revision');
        const updated = Math.floor(Date.parse(commit.commit.committer.date) / 1000);
        assert(Number.isSafeInteger(updated) && updated > 0 && updated <= now + 300, 'Invalid source date');
        const base = `https://raw.githubusercontent.com/${source.repo}/${commit.sha}/`;
        let license = (await fetchText(base + source.licensePath)).trim();
        if (source.id === 'matomo_referrer_spam') {
            assert(license.includes('## License\n'), 'Missing license declaration');
            license = license.split('## License\n').at(-1).trim();
        }
        assert(hash(license) === source.licenseHash, 'Source license changed: review required');
        const body = await fetchText(base + source.path);
        if (source.domain) assert(body.includes(source.domain), 'Provider namespace evidence changed');
        datasets.push({
            id: source.id, category: source.category, license: source.license,
            license_text: license, license_sha256: hash(license),
            url: `https://github.com/${source.repo}/blob/${commit.sha}/${source.path}`,
            revision: commit.sha, updated_at_unix: updated,
            fetched_at_unix: now, expires_at_unix: now + 7 * 86400,
            domains: source.domain ? [source.domain] : source.id === 'fakefilter_recent' ? monitoredDomains(body, now) : domains(body),
            allowlist: []
        });
    }
    const cc0 = datasets.find(s => s.license === 'CC0-1.0').license_text;
    for (const [file, id, category] of [
        ['reviewed-free-subdomains.json', 'reviewed_free_subdomains', 'free_subdomain'],
        ['reviewed-domain-disputes.json', 'reviewed_disposable_disputes', 'disposable_review']
    ]) {
        phase = id;
        const reviewed = await readFile(resolve(root, 'data', file), 'utf8');
        const curated = JSON.parse(reviewed);
        assert(curated.license === 'CC0-1.0' && Array.isArray(curated.entries) && curated.entries.length > 0, 'Invalid reviewed source');
        assert(Number.isSafeInteger(curated.reviewed_at_unix) && curated.reviewed_at_unix <= now + 300, 'Invalid review date');
        assert(Number.isSafeInteger(curated.expires_at_unix) && curated.expires_at_unix > curated.reviewed_at_unix && curated.expires_at_unix <= curated.reviewed_at_unix + 30 * 86400, 'Invalid review expiry');
        for (const entry of curated.entries) assert(/^https:\/\/[^\s?#@]+$/.test(entry.evidence_url), 'Invalid evidence URL');
        datasets.push({
            id, category, license: 'CC0-1.0', license_text: cc0, license_sha256: hash(cc0),
            url: `https://github.com/Mokto/openfingerprint/blob/main/api/data/${file}`,
            revision: hash(reviewed), updated_at_unix: curated.reviewed_at_unix,
            fetched_at_unix: curated.reviewed_at_unix, expires_at_unix: curated.expires_at_unix,
            domains: domains(curated.entries.map(s => s.domain).join('\n')), allowlist: []
        });
    }
    const result = JSON.stringify({ version: 1, sources: datasets }) + '\n';
    assert(Buffer.byteLength(result) <= limit, 'Snapshot too large');
    return result;
}

export async function update(output, fetchText = download) {
    const data = await snapshot(fetchText);
    await mkdir(dirname(output), { recursive: true });
    const temporary = `${output}.${randomBytes(8).toString('hex')}.tmp`;
    try {
        const file = await open(temporary, 'wx', 0o644);
        try { await file.writeFile(data); await file.sync(); } finally { await file.close(); }
        await rename(temporary, output);
    } finally { await unlink(temporary).catch(() => {}); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const { values } = parseArgs({ options: { output: { type: 'string', default: resolve(root, 'data/domains.json') } } });
        await update(resolve(values.output));
        console.log('Open domain snapshot updated atomically; refresh the API to load it.');
    } catch (error) {
        const reason = error instanceof assert.AssertionError ? error.message : 'Source transport or filesystem error';
        console.error(`Domain update failed at ${phase}: ${reason}. The previous snapshot was preserved.`);
        process.exitCode = 1;
    }
}
