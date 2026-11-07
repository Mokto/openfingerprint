// Builds data/whois-servers.json: the IANA WHOIS server of every TLD without an RDAP service.
import assert from 'node:assert/strict';
import { lookup } from 'node:dns/promises';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { fileURLToPath } from 'node:url';

const data = fileURLToPath(new URL('./data/', import.meta.url));
// These registries refuse anonymous port-43 queries: .ch/.li point to a web form, .es serves
// only registered IP addresses and .hu answers with a banner and no data.
const refused = new Set(['ch', 'li', 'es', 'hu']);

function whois(host, query) {
    return new Promise((resolve, reject) => {
        const socket = connect(43, host);
        let out = '';
        socket.setTimeout(10000, () => socket.destroy(new Error('timeout')));
        socket.on('connect', () => socket.write(`${query}\r\n`));
        socket.on('data', chunk => { out += chunk; if (out.length > 65536) socket.destroy(new Error('too large')); });
        socket.on('close', () => resolve(out));
        socket.on('error', reject);
    });
}

const tlds = (await (await fetch('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', { redirect: 'error', signal: AbortSignal.timeout(20000) })).text())
    .split('\n').filter(l => l && !l.startsWith('#')).map(l => l.trim().toLowerCase());
assert(tlds.length > 1000, 'Unexpected IANA TLD list');
const rdap = new Set(JSON.parse(await readFile(data + 'rdap-dns.json', 'utf8')).services.flatMap(([names]) => names));
const servers = {};
for (const tld of tlds.filter(t => !rdap.has(t) && !refused.has(t))) {
    const host = (await whois('whois.iana.org', tld).catch(() => '')).match(/^whois:\s*(\S+)/m)?.[1]?.toLowerCase();
    if (host && /^[a-z0-9.-]+$/.test(host) && await lookup(host).then(() => true, () => false)) servers[tld] = host;
    await new Promise(r => setTimeout(r, 200));
}
assert(Object.keys(servers).length >= 50, `Only ${Object.keys(servers).length} WHOIS servers resolved; keeping the previous file`);
const out = data + 'whois-servers.json';
await writeFile(out + '.tmp', JSON.stringify({ source: 'https://www.iana.org/domains/root/db', servers }, null, 1) + '\n');
await rename(out + '.tmp', out);
console.log(`WHOIS servers for ${Object.keys(servers).length} TLDs without RDAP.`);
