// Finds MX infrastructure that public disposable-domain lists cluster on and popular sites avoid.
// node api/mine-disposable-infra.mjs <source-map.txt> <tranco-top-1m.csv> [tranco-rows=300000]
// <source-map.txt>: "source:domain" lines, as in disposable/disposable-email-domains. Prints candidates for
// review; api/data/disposable-infrastructure.json lists only the reviewed ones.
import { readFileSync } from 'node:fs';
import { Resolver } from 'node:dns/promises';
import { pathToFileURL } from 'node:url';

export function suffixMatcher(pslText) {
    const icann = pslText.split('// ===BEGIN ICANN DOMAINS===')[1].split('// ===END ICANN DOMAINS===')[0];
    const rules = new Set(), exceptions = new Set();
    for (const line of icann.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('//'))) (line[0] === '!' ? exceptions : rules).add(line.replace(/^!/, ''));
    return host => {
        const labels = host.toLowerCase().replace(/\.$/, '').split('.');
        let length = 1;
        for (let i = 0; i < labels.length; i++) {
            const name = labels.slice(i).join('.');
            if (exceptions.has(name)) { length = labels.length - i - 1; break; }
            if (rules.has(name) || rules.has(['*', ...labels.slice(i + 1)].join('.'))) { length = Math.max(length, labels.length - i); break; }
        }
        return labels.length > length ? labels.slice(-(length + 1)).join('.') : null;
    };
}

// How many domains have any MX host under each registered domain.
export function tally(mxByDomain, registered) {
    const counts = {};
    for (const hosts of Object.values(mxByDomain)) for (const name of new Set(hosts.map(registered).filter(Boolean))) counts[name] = (counts[name] || 0) + 1;
    return counts;
}

async function lookup(domains) {
    const resolvers = ['1.1.1.1', '8.8.8.8', '9.9.9.9'].map(s => { const r = new Resolver({ timeout: 3000, tries: 2 }); r.setServers([s]); return r; });
    const out = {}; let next = 0;
    await Promise.all(Array.from({ length: 48 }, async (_, w) => {
        while (next < domains.length) {
            const d = domains[next++];
            try { out[d] = (await resolvers[w % 3].resolveMx(d)).map(m => m.exchange.toLowerCase().replace(/\.$/, '')); } catch { out[d] = []; }
        }
    }));
    return out;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    const [sourceMap, tranco, rows = '300000'] = process.argv.slice(2);
    const registered = suffixMatcher(await (await fetch('https://publicsuffix.org/list/public_suffix_list.dat')).text());
    const listed = [...new Set(readFileSync(sourceMap, 'utf8').split('\n').map(l => l.slice(l.lastIndexOf(':') + 1).trim().toLowerCase()).filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)))];
    const popular = readFileSync(tranco, 'utf8').split(/\r?\n/).slice(0, +rows).map(l => l.split(',')[1]).filter(Boolean);
    const [onLists, onPopular] = [tally(await lookup(listed), registered), tally(await lookup(popular), registered)];
    console.log('registered domain'.padEnd(30), 'listed_domains popular_sites');
    for (const [name, n] of Object.entries(onLists).filter(([, n]) => n >= 50).sort((a, b) => b[1] - a[1])) if ((onPopular[name] || 0) <= 3) console.log(name.padEnd(30), String(n).padStart(14), String(onPopular[name] || 0).padStart(13));
}
