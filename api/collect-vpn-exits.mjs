import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, stat, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';
import { acquireLock, atomic, validate, vpnExits } from './update-network-data.mjs';

const execute = promisify(execFile);
const docker = (args, signal) => execute('docker', args, { signal, timeout: 45000, maxBuffer: 65536 });

export async function measure(profile, config, name, { signal, run = docker, pause = sleep } = {}) {
    const probe = name + '-observer';
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(150000)].filter(Boolean));
    const remove = async () => {
        await run(['rm', '--force', probe, name]).catch(() => {});
        try {
            const { stdout } = await run(['ps', '--all', '--quiet', '--filter', `name=^/${name}(-observer)?$`]);
            assert(stdout.trim() === '');
        } catch {
            throw Object.assign(new Error('VPN cleanup could not be confirmed'), { code: 'VPN_CLEANUP_FAILED' });
        }
    };
    await remove();
    try {
        const mounts = ['--mount', `type=bind,src=${profile.config},dst=/gluetun/${profile.type === 'openvpn' ? 'custom.conf' : 'wireguard/wg0.conf'},readonly`];
        const env = ['--env', 'VPN_SERVICE_PROVIDER=custom', '--env', `VPN_TYPE=${profile.type}`, '--env', 'FIREWALL=on'];
        if (profile.type === 'openvpn') {
            env.push('--env', 'OPENVPN_CUSTOM_CONFIG=/gluetun/custom.conf');
            for (const [field, secret] of [['usernameFile', 'openvpn_user'], ['passwordFile', 'openvpn_password']]) {
                mounts.push('--mount', `type=bind,src=${profile[field]},dst=/run/secrets/${secret},readonly`);
            }
        } else {
            env.push('--env', 'WIREGUARD_IMPLEMENTATION=userspace');
        }
        await run(['run', '--detach', '--rm', '--pull=never', '--name', name, '--label', 'openfingerprint.vpn-collector=true',
            '--cap-add=NET_ADMIN', '--device=/dev/net/tun', '--security-opt=no-new-privileges', ...mounts, ...env,
            'openfingerprint-vpn-tunnel:local'], deadline);
        const healthy = async () => (await run(['inspect', '--format', '{{.State.Health.Status}}', name], deadline)).stdout.trim() === 'healthy';
        let ready = false;
        for (let attempt = 0; attempt < 60; attempt++) {
            if (await healthy()) { ready = true; break; }
            await pause(2000, undefined, { signal: deadline });
        }
        assert(ready, 'VPN did not become healthy');
        const { stdout } = await run(['run', '--rm', '--pull=never', '--name', probe, '--label', 'openfingerprint.vpn-collector=true', '--network', `container:${name}`,
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', 'openfingerprint-vpn-observer:local',
            '--provider', profile.provider, '--endpoint', config.endpoint, '--attribution', config.attribution, '--confirm-vpn', '--cc0'], deadline);
        assert(await healthy(), 'VPN lost health during measurement');
        return JSON.parse(stdout);
    } finally { await remove(); }
}

export async function collect(configPath, output, { signal, probe = measure } = {}) {
    configPath = resolve(configPath);
    output = resolve(output);
    assert(configPath !== output, 'Config and output must be different files');
    const file = await open(configPath, 'r');
    let config;
    try {
        const info = await file.stat();
        assert(info.isFile() && info.size <= 65536, 'Config must be a bounded regular file');
        config = JSON.parse(await file.readFile('utf8'));
    } finally { await file.close(); }
    assert(config.version === 1 && config.cc0 === true, 'Version 1 and explicit CC0 consent are required');
    assert(Object.keys(config).every(key => ['version', 'cc0', 'endpoint', 'attribution', 'profiles'].includes(key)), 'Unknown config field');
    const endpoint = new URL(config.endpoint);
    assert(endpoint.protocol === 'https:' && !endpoint.username && !endpoint.password && !endpoint.hash && endpoint.href.length <= 512, 'Invalid echo endpoint');
    config.endpoint = endpoint.href;
    assert(typeof config.attribution === 'string' && config.attribution.length > 0 && config.attribution.length <= 256 && !/[\p{Cc}]/u.test(config.attribution), 'Invalid attribution');
    assert(Array.isArray(config.profiles) && config.profiles.length > 0 && config.profiles.length <= 64, 'Configure 1–64 VPN profiles');
    const ids = new Set();
    for (const profile of config.profiles) {
        assert(Object.keys(profile).every(key => ['id', 'provider', 'type', 'config', 'usernameFile', 'passwordFile'].includes(key)), 'Unknown profile field');
        assert(typeof profile.id === 'string' && /^[a-z0-9][a-z0-9-]{0,47}$/.test(profile.id) && !ids.has(profile.id), 'Invalid/duplicate profile ID');
        ids.add(profile.id);
        assert(typeof profile.provider === 'string' && /^[A-Za-z0-9][A-Za-z0-9 _-]{0,63}$/.test(profile.provider), 'Invalid provider');
        assert(['openvpn', 'wireguard'].includes(profile.type), 'Invalid VPN type');
        assert(profile.type === 'openvpn' || (!profile.usernameFile && !profile.passwordFile), 'WireGuard credentials belong in its config');
        for (const key of profile.type === 'openvpn' ? ['config', 'usernameFile', 'passwordFile'] : ['config']) {
            assert(typeof profile[key] === 'string' && profile[key].length > 0 && !/[,\p{Cc}]/u.test(profile[key]), 'Invalid profile file path');
            profile[key] = resolve(dirname(configPath), profile[key]);
            const info = await stat(profile[key]);
            assert(info.isFile() && info.size > 0 && info.size <= 1024 * 1024, 'Invalid profile/credential file');
            assert(profile[key] !== output, 'Output cannot overwrite a profile or credential');
        }
    }
    await mkdir(dirname(output), { recursive: true });
    const lost = new AbortController();
    signal = AbortSignal.any([signal, lost.signal].filter(Boolean));
    signal.throwIfAborted();
    // Cancellation must not release the lock before Docker cleanup finishes.
    const lock = await acquireLock(output + '.lock');
    lock.once('exit', () => lost.abort());
    const temporary = output + `.${randomBytes(8).toString('hex')}.tmp`;
    const failures = [];
    let refreshed = 0;
    try {
        let previous;
        try {
            previous = await vpnExits(output, Math.floor(Date.now() / 1000), { allowExpired: true });
            await atomic(temporary, JSON.stringify({ version: 1, vpn_exits: previous }));
            await validate(temporary, signal);
        } catch (error) { if (error.code !== 'ENOENT') throw error; }
        const providers = new Set(config.profiles.map(profile => profile.provider));
        for (const profile of config.profiles) {
            signal?.throwIfAborted();
            const name = 'ofp-vpn-' + createHash('sha256').update(output).digest('hex').slice(0, 12) + '-' + profile.id;
            try {
                const started = Math.floor(Date.now() / 1000);
                const source = await probe(profile, config, name, { signal });
                const now = Math.floor(Date.now() / 1000);
                assert(source.entries?.length === 1 && source.entries[0].provider === profile.provider
                    && source.entries[0].evidence_url === config.endpoint
                    && source.entries[0].observed_at_unix >= started && source.entries[0].observed_at_unix <= now, 'Invalid measurement');
                const entries = new Map();
                for (const input of [previous, source].filter(Boolean)) {
                    for (const original of input.entries) {
                        const entry = { ...original, expires_at_unix: Math.min(input.metadata.expires_at_unix, original.expires_at_unix ?? original.observed_at_unix + 86400) };
                        if (!providers.has(entry.provider) || entry.expires_at_unix <= now) continue;
                        const key = `${entry.provider}|${entry.ip}`;
                        if (!entries.has(key) || entries.get(key).observed_at_unix < entry.observed_at_unix) entries.set(key, entry);
                    }
                }
                const candidate = { metadata: source.metadata, entries: [...entries.values()] };
                await atomic(temporary, JSON.stringify({ version: 1, vpn_exits: candidate }));
                await validate(temporary, signal);
                signal?.throwIfAborted();
                await atomic(output, JSON.stringify(candidate) + '\n');
                previous = candidate;
                refreshed++;
                console.log(`VPN profile ${profile.id}: observation published.`);
            } catch (error) {
                signal?.throwIfAborted();
                if (error.code === 'VPN_CLEANUP_FAILED') throw error;
                failures.push(profile.id);
                console.warn(`VPN profile ${profile.id} failed; previous observations keep their original expiry.`);
            }
        }
        assert(refreshed > 0, 'No exits measured; previous feed unchanged');
        return { failures, refreshed };
    } finally {
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
        const { values } = parseArgs({ options: { config: { type: 'string' }, output: { type: 'string' } } });
        assert(values.config && values.output, '--config and --output are required');
        const controller = new AbortController();
        process.once('SIGINT', () => controller.abort());
        process.once('SIGTERM', () => controller.abort());
        const result = await collect(values.config, values.output, { signal: controller.signal });
        if (result.failures.length) process.exitCode = 1;
    } catch (error) {
        if (error.code === 'VPN_CLEANUP_FAILED') console.error('VPN cleanup could not be confirmed; inspect managed containers before retrying.');
        console.error('VPN collection failed; check Docker, config, secret files and container health. No credentials or container logs are printed.');
        process.exitCode = 1;
    }
}
