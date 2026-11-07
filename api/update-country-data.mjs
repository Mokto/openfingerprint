import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { gunzipSync } from 'node:zlib';

const page = 'https://db-ip.com/db/download/ip-to-country-lite';
const limit = 32 * 1024 * 1024;

async function download(url, max, fetcher) {
    const response = await fetcher(url, { signal: AbortSignal.timeout(60000), redirect: 'error' });
    assert(response.ok && response.body, 'Country download failed');
    assert(Number(response.headers.get('content-length') ?? 0) <= max, 'Country download exceeds limit');
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    try {
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            length += value.length;
            assert(length <= max, 'Country download exceeds limit');
            chunks.push(value);
        }
    } finally {
        await reader.cancel();
    }
    return Buffer.concat(chunks);
}

export async function refresh(output, fetcher = fetch) {
    const html = (await download(page, 512 * 1024, fetcher)).toString('utf8');
    const match = /https:\/\/download\.db-ip\.com\/free\/dbip-country-lite-\d{4}-\d{2}\.mmdb\.gz(?=['"])/.exec(html);
    assert(match, 'Country download link unavailable');
    const checksum = [...html.slice(0, match.index).matchAll(/SHA1SUM<\/dt>\s*<dd[^>]*>([a-f0-9]{40})<\/dd>/g)].at(-1)?.[1];
    assert(checksum, 'Country checksum unavailable');
    const compressed = await download(match[0], limit, fetcher);
    const bytes = gunzipSync(compressed, { maxOutputLength: limit });
    assert.equal(createHash('sha1').update(bytes).digest('hex'), checksum, 'Country checksum mismatch');
    await mkdir(dirname(output), { recursive: true });
    if (await readFile(output).then(b => b.equals(bytes), () => false)) return;
    const temporary = `${output}.${randomBytes(8).toString('hex')}.tmp`;
    try {
        await writeFile(temporary, bytes, { flag: 'wx', mode: 0o644, flush: true });
        execFileSync(process.env.OPENFINGERPRINT_COUNTRY_VALIDATOR || 'openfingerprint-api',
            ['--validate-country', temporary, output], { timeout: 30000, stdio: 'ignore' });
        await rename(temporary, output);
    } finally {
        await unlink(temporary).catch(() => {});
    }
    console.log('Country snapshot refreshed (IP Geolocation by DB-IP, CC-BY-4.0).');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const { values } = parseArgs({ options: { output: { type: 'string' }, loop: { type: 'boolean' } } });
    assert(values.output, '--output is required');
    do {
        let delay = 86400000;
        try {
            await refresh(resolve(values.output));
        } catch {
            console.error('Country refresh failed; retaining the previous file.');
            if (!values.loop) { process.exitCode = 1; break; }
            delay = 3600000;
        }
        if (values.loop) await setTimeout(delay);
    } while (values.loop);
}
