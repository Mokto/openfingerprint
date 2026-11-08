// Builds data/tld-prices.json: which generic TLDs a registrar sells at teaser prices.
import assert from 'node:assert/strict';
import { rename, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const out = fileURLToPath(new URL('./data/tld-prices.json', import.meta.url));
const url = 'https://api.porkbun.com/api/json/v3/pricing/get';
export const threshold = 3;

// Country codes stay out of "cheap": registries such as .de are inexpensive at every price level.
// IDN TLDs are skipped too, since they cannot be told from IDN country codes without the IANA type.
export function derive(pricing) {
    const cheap = [], other = [];
    for (const [tld, { registration }] of Object.entries(pricing)) {
        const price = Number(registration);
        if (!/^[a-z0-9-]+$/.test(tld) || !(price >= 0)) continue;
        (price <= threshold && tld.length > 2 && !tld.startsWith('xn--') ? cheap : other).push(tld);
    }
    return { cheap: cheap.sort(), other: other.sort() };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const response = await fetch(url, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
        redirect: 'error', signal: AbortSignal.timeout(30000),
    });
    assert(response.ok, `Pricing request failed: ${response.status}`);
    const body = await response.json();
    assert.equal(body.status, 'SUCCESS');
    const { cheap, other } = derive(body.pricing);
    // A truncated or reshaped answer must not rewrite the list.
    assert(cheap.length + other.length > 500, 'Unexpectedly few priced TLDs; keeping the previous file');
    assert(other.includes('com') && other.includes('de') && cheap.includes('xyz'), 'Reference TLDs are misclassified');
    await writeFile(out + '.tmp', JSON.stringify({
        source: 'https://porkbun.com/api/json/v3/documentation',
        rule: `first-year registration price of ${threshold} USD or less, generic TLDs only`,
        cheap, other,
    }, null, 1) + '\n');
    await rename(out + '.tmp', out);
    console.log(`${cheap.length} cheap and ${other.length} other priced TLDs.`);
}
