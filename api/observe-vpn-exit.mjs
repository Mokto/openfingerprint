import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { download } from './update-network-data.mjs';

export async function observe({ provider, endpoint, attribution, confirmVpn, cc0 }, fetchBytes = url => download(url, undefined, 4096, 'application/json')) {
    assert(confirmVpn && cc0, 'Confirm the VPN connection and CC0 dedication with --confirm-vpn and --cc0');
    assert(typeof provider === 'string' && /^[A-Za-z0-9][A-Za-z0-9 _-]{0,63}$/.test(provider), 'Invalid provider');
    assert(typeof attribution === 'string' && attribution.length > 0 && attribution.length <= 256 && !/[\p{Cc}]/u.test(attribution), 'Invalid attribution');
    const url = new URL(endpoint);
    assert(url.protocol === 'https:' && !url.username && !url.password && !url.hash && url.href.length <= 512, 'Use an HTTPS IP echo endpoint without credentials or fragment');
    const bytes = await fetchBytes(url.href);
    assert(bytes.length <= 4096, 'IP echo response exceeds size limit');
    const { ip } = JSON.parse(bytes);
    assert(isIP(ip), 'IP echo must return {"ip":"<address>"}');
    const now = Math.floor(Date.now() / 1000);
    return {
        metadata: {
            id: 'observed_vpn_exits', license: 'CC0-1.0', license_url: 'https://creativecommons.org/publicdomain/zero/1.0/',
            attribution, url: url.href, revision: createHash('sha256').update(bytes).digest('hex'),
            updated_at_unix: now, fetched_at_unix: now, expires_at_unix: now + 86400
        },
        entries: [{ ip, provider, observed_at_unix: now, evidence_url: url.href }]
    };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const { values } = parseArgs({ options: {
            provider: { type: 'string' }, endpoint: { type: 'string' }, attribution: { type: 'string' },
            'confirm-vpn': { type: 'boolean' }, cc0: { type: 'boolean' }
        } });
        const source = await observe({ ...values, confirmVpn: values['confirm-vpn'] });
        console.log(JSON.stringify(source, null, 2));
    } catch (error) {
        console.error(`VPN exit observation failed: ${error.message}`);
        process.exitCode = 1;
    }
}
