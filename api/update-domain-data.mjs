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
    // Only domains the aggregator scraped from live temp-mail services; its copies of published lists are skipped.
    { id: 'disposable_live_services', repo: 'disposable/disposable-email-domains', branch: 'master', path: 'domains_source_map.txt', category: 'disposable', license: 'MIT', licensePath: 'LICENSE', licenseHash: '7ce15ed3b57f1045db3ba34e3e71ae5d629ee2c766cf2035fe09990e08892ab2', maxBytes: 32 * 1024 * 1024, maxAgeDays: 3 },
    { id: 'fakefilter_recent', repo: '7c/fakefilter', branch: 'main', path: 'json/data.json', category: 'disposable', license: 'BSD-3-Clause', licensePath: 'LICENSE.md', licenseHash: '25e04934f5510427abb55d007d942a58184b095a2e40618b0a4b76b69b3da59a' },
    { id: 'is_a_dev', repo: 'is-a-dev/register', branch: 'main', path: 'README.md', domain: 'is-a.dev', category: 'free_subdomain', license: 'MIT', licensePath: 'LICENSE', licenseHash: '2ffd9de047964b8cb6e526079da1dc6c8ffd3d1691faabb6433b4100e5e2790b' },
    { id: 'is_a_bot', repo: 'free-domains/is-a.bot', branch: 'main', path: 'README.md', domain: 'is-a.bot', category: 'free_subdomain', license: 'MIT', licensePath: 'LICENSE', licenseHash: '14979e0fc8469d414ea35d1c3e08ebdd3b336ac07e55c0d089413bdcaeb88046' },
    { id: 'matomo_referrer_spam', repo: 'matomo-org/referrer-spam-list', branch: 'master', path: 'spammers.txt', category: 'referrer_spam', license: 'LicenseRef-Public-Domain', licensePath: 'README.md', licenseHash: '6b509c9d22e2c323586c8b07c23f33c2edda65faf23e4db6c94a226a5a6cff2e' }
];

// Upstream mistakes here would accuse ordinary mailboxes directly or, through
// MX hosts, every domain whose mail they route, so listings are never accepted.
export const protectedDomains = [
    '126.com', '163.com', 'aol.com', 'apple.com', 'att.net', 'comcast.net', 'daum.net',
    'fastmail.com', 'free.fr', 'gmail.com', 'gmx.com', 'gmx.net', 'google.com', 'googlemail.com',
    'hotmail.com', 'icloud.com', 'ionos.com', 'live.com', 'mac.com', 'mail.com', 'mail.ru', 'me.com',
    'messagingengine.com', 'microsoft.com', 'mimecast.com', 'msn.com', 'naver.com', 'orange.fr',
    'outlook.com', 'ovh.net', 'pphosted.com', 'proton.me', 'protonmail.ch', 'protonmail.com', 'qq.com',
    'secureserver.net', 't-online.de', 'tuta.com', 'tutanota.com', 'verizon.net', 'web.de', 'yahoo.com',
    'yahoodns.net', 'yandex.com', 'yandex.net', 'yandex.ru', 'zoho.com', 'zohomail.com'
];
export function unprotected(entries, extra = []) {
    const all = [...protectedDomains, ...extra];
    const hit = d => all.some(p => d === p || d.endsWith('.' + p) || p.endsWith('.' + d));
    return { kept: entries.filter(d => !hit(d)), dropped: entries.filter(hit) };
}

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

// `source:domain` lines; published lists (GitHub raw files, gists, throwaway.cloud) are other
// people's lists, the rest are temp-mail services the aggregator reads directly.
export function liveServiceDomains(text) {
    const listed = text.split(/\r?\n/).filter(Boolean).map(line => {
        const at = line.lastIndexOf(':');
        assert(at > 0, 'Invalid source map line');
        return [line.slice(0, at), line.slice(at + 1)];
    }).filter(([source]) => !/^https:\/\/(raw\.githubusercontent\.com|gist\.githubusercontent\.com|throwaway\.cloud)\//.test(source));
    assert(listed.length >= 500, 'Too few live-service domains: the source map format may have changed');
    return domains(listed.map(([, domain]) => domain).join('\n'));
}

// FakeFilter rounds firstseen/lastseen to the nearest 10,000 s but stamps `t` exactly, so lastseen can be up to one step after `t`.
const observationRounding = 10000;

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
        assert(Number.isSafeInteger(entry.firstseen) && entry.firstseen > 0 && Number.isSafeInteger(entry.lastseen) && entry.firstseen <= entry.lastseen && entry.lastseen <= feed.t + observationRounding && entry.lastseen <= now + observationRounding, 'Invalid monitored observation time');
    }
    return domains(entries.filter(([, entry]) => entry.lastseen >= now - 14 * 86400).map(([name]) => name).join('\n'));
}

const hash = text => createHash('sha256').update(text).digest('hex');
export async function download(url, max = limit) {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(20000), headers: { Accept: 'application/vnd.github+json' } });
    assert(response.status === 200, `Public source unavailable (HTTP ${response.status})`);
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > max) { await reader.cancel(); throw new Error('Public source too large'); }
        chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
}

const reviewedFiles = [
    ['reviewed-free-subdomains.json', 'reviewed_free_subdomains', 'free_subdomain'],
    ['reviewed-domain-disputes.json', 'reviewed_disposable_disputes', 'disposable_review'],
    ['reviewed-public-mailboxes.json', 'reviewed_public_mailboxes', 'public_mailbox'],
    ['reviewed-relays.json', 'reviewed_relays', 'relay']
];

export async function snapshot(fetchText = download, now = Math.floor(Date.now() / 1000)) {
    const datasets = [];
    const mailboxes = JSON.parse(await readFile(resolve(root, 'data', 'reviewed-public-mailboxes.json'), 'utf8')).entries.map(e => e.domain);
    for (const source of sources) {
        phase = source.id;
        const commit = JSON.parse(await fetchText(`https://api.github.com/repos/${source.repo}/commits/${source.branch}`));
        assert(/^[a-f0-9]{40}$/.test(commit.sha), 'Invalid source revision');
        const updated = Math.floor(Date.parse(commit.commit.committer.date) / 1000);
        assert(Number.isSafeInteger(updated) && updated > 0 && updated <= now + 300, 'Invalid source date');
        if (source.maxAgeDays) assert(updated >= now - source.maxAgeDays * 86400, 'Source is stale');
        const base = `https://raw.githubusercontent.com/${source.repo}/${commit.sha}/`;
        let license = (await fetchText(base + source.licensePath)).trim();
        if (source.id === 'matomo_referrer_spam') {
            assert(license.includes('## License\n'), 'Missing license declaration');
            license = license.split('## License\n').at(-1).trim();
        }
        assert(hash(license) === source.licenseHash, 'Source license changed: review required');
        const body = await fetchText(base + source.path, source.maxBytes);
        if (source.domain) assert(body.includes(source.domain), 'Provider namespace evidence changed');
        const listed = source.domain ? [source.domain] : source.id === 'fakefilter_recent' ? monitoredDomains(body, now) : source.id === 'disposable_live_services' ? liveServiceDomains(body) : domains(body);
        const { kept, dropped } = source.domain ? { kept: listed, dropped: [] } : unprotected(listed, mailboxes);
        if (dropped.length) console.warn(`${source.id}: ignored ${dropped.length} listing(s) of protected mail domains: ${dropped.slice(0, 20).join(', ')}`);
        datasets.push({
            id: source.id, category: source.category, license: source.license,
            license_text: license, license_sha256: hash(license),
            url: `https://github.com/${source.repo}/blob/${commit.sha}/${source.path}`,
            revision: commit.sha, updated_at_unix: updated,
            fetched_at_unix: now, expires_at_unix: now + 7 * 86400,
            domains: kept,
            allowlist: []
        });
    }
    const cc0 = datasets.find(s => s.license === 'CC0-1.0').license_text;
    for (const [file, id, category] of reviewedFiles) {
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

const serviceAccount = '/var/run/secrets/kubernetes.io/serviceaccount';
export async function kubernetes(name, data, { dir = serviceAccount, env = process.env } = {}) {
    phase = 'configmap';
    const [token, namespace] = await Promise.all(['token', 'namespace'].map(f => readFile(`${dir}/${f}`, 'utf8').then(s => s.trim())));
    const host = env.KUBERNETES_SERVICE_HOST;
    assert(host && /^\d+$/.test(env.KUBERNETES_SERVICE_PORT ?? ''), 'Not running in a Kubernetes pod');
    const base = `https://${host.includes(':') ? `[${host}]` : host}:${env.KUBERNETES_SERVICE_PORT}/api/v1/namespaces/${encodeURIComponent(namespace)}/configmaps`;
    const call = async (url, method, body, type) => {
        const response = await fetch(url, {
            method, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(20000),
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': type, Accept: 'application/json' }
        });
        await response.body?.cancel();
        return response.status;
    };
    const content = { data: { 'domains.json': data } };
    let status = await call(`${base}/${name}`, 'PATCH', content, 'application/merge-patch+json');
    if (status === 404) status = await call(base, 'POST', { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name }, ...content }, 'application/json');
    assert(status === 200 || status === 201, `ConfigMap update failed (HTTP ${status})`);
}

export async function publish(name, fetchText = download, write = kubernetes) {
    assert(/^[a-z0-9](?:[a-z0-9-]{0,251}[a-z0-9])?$/.test(name), 'Invalid ConfigMap name');
    const data = await snapshot(fetchText);
    // ponytail: ConfigMaps cap at 1 MiB; move to a volume or object store if sources outgrow it.
    assert(Buffer.byteLength(data) <= 1000000, 'Snapshot exceeds the ConfigMap size limit');
    await write(name, data);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const { values } = parseArgs({ options: { output: { type: 'string' }, configmap: { type: 'string' } } });
        assert(!(values.output && values.configmap), 'Use --output or --configmap, not both');
        if (values.configmap) {
            await publish(values.configmap);
            console.log(`Open domain snapshot published to ConfigMap ${values.configmap}; the API reloads it automatically.`);
        } else {
            await update(resolve(values.output ?? resolve(root, 'data/domains.json')));
            console.log('Open domain snapshot updated atomically; the API reloads an override file automatically.');
        }
    } catch (error) {
        const reason = error instanceof assert.AssertionError ? error.message : 'Source transport or filesystem error';
        console.error(`Domain update failed at ${phase}: ${reason}. The previous snapshot was preserved.`);
        process.exitCode = 1;
    }
}
