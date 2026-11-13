import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { collect, measure } from './collect-vpn-exits.mjs';
import { observe } from './observe-vpn-exit.mjs';

const directory = await mkdtemp(resolve(tmpdir(), 'openfingerprint-vpn-collector-'));
const output = resolve(directory, 'vpn-exits.json');
const configPath = resolve(directory, 'collector.json');
const config = {
    version: 1, cc0: true, endpoint: 'https://echo.example.test/ip', attribution: 'Test operator',
    profiles: [
        { id: 'privatevpn-dk', provider: 'PrivateVPN', type: 'openvpn', config: 'privatevpn.ovpn', usernameFile: 'username', passwordFile: 'password' },
        { id: 'ivpn-dk', provider: 'IVPN', type: 'wireguard', config: 'ivpn.conf' }
    ]
};
const measured = profile => observe({ provider: profile.provider, endpoint: config.endpoint, attribution: config.attribution, confirmVpn: true, cc0: true }, async () => Buffer.from('{"ip":"8.8.4.4"}'));
try {
    for (const name of ['privatevpn.ovpn', 'ivpn.conf', 'username', 'password']) await writeFile(resolve(directory, name), 'test secret');
    await writeFile(configPath, JSON.stringify(config));
    const previous = await measured(config.profiles[0]);
    const now = previous.metadata.updated_at_unix;
    previous.metadata.updated_at_unix -= 600;
    previous.metadata.fetched_at_unix -= 600;
    previous.metadata.expires_at_unix = now + 120;
    previous.entries = [
        { ip: '8.8.8.8', provider: 'PrivateVPN', observed_at_unix: now - 600, evidence_url: config.endpoint },
        { ip: '9.9.9.9', provider: 'IVPN', observed_at_unix: now - 600, evidence_url: config.endpoint },
        { ip: '1.0.0.1', provider: 'IVPN', observed_at_unix: now - 86400, evidence_url: config.endpoint }
    ];
    await writeFile(output, JSON.stringify(previous));
    const result = await collect(configPath, output, { probe: async profile => {
        assert(profile.config.startsWith(directory));
        if (profile.id === 'ivpn-dk') throw new Error('secret failure must not be printed');
        return measured(profile);
    } });
    assert.deepEqual(result, { failures: ['ivpn-dk'], refreshed: 1 });
    const source = JSON.parse(await readFile(output));
    assert.equal(source.entries.length, 3);
    assert.equal(source.entries.find(entry => entry.ip === '9.9.9.9').observed_at_unix, now - 600);
    assert.equal(source.entries.find(entry => entry.ip === '9.9.9.9').expires_at_unix, now + 120);
    assert.equal(source.entries.find(entry => entry.ip === '8.8.8.8').expires_at_unix, now + 120);
    assert.equal(source.entries.find(entry => entry.ip === '8.8.8.8').observed_at_unix, now - 600);
    assert.equal(source.entries.find(entry => entry.ip === '8.8.4.4').provider, 'PrivateVPN');
    const preserved = await readFile(output, 'utf8');
    await assert.rejects(collect(configPath, output, { probe: async () => { throw new Error('offline'); } }), /No exits measured/);
    assert.equal(await readFile(output, 'utf8'), preserved);
    await assert.rejects(collect(configPath, output, { probe: async profile => {
        const invalid = await measured(profile);
        invalid.entries[0].ip = '127.0.0.1';
        return invalid;
    } }), /No exits measured/);
    assert.equal(await readFile(output, 'utf8'), preserved);
    for (const override of [{ cc0: false }, { endpoint: 'http://echo.example.test' }, { profiles: [config.profiles[0], config.profiles[0]] }, { profiles: [{ ...config.profiles[0], type: 'unknown' }] }]) {
        await writeFile(configPath, JSON.stringify({ ...config, ...override }));
        await assert.rejects(collect(configPath, output, { probe: () => assert.fail('Invalid configuration must not start a VPN') }));
        assert.equal(await readFile(output, 'utf8'), preserved);
    }
    await writeFile(configPath, JSON.stringify(config));
    const controller = new AbortController();
    let entered, finishCleanup;
    const blocked = new Promise(resolve => { entered = resolve; });
    const cleanup = new Promise(resolve => { finishCleanup = resolve; });
    const running = collect(configPath, output, { signal: controller.signal, probe: async (_profile, _config, _name, { signal }) => {
        entered();
        await new Promise((_, reject) => signal.addEventListener('abort', async () => { await cleanup; reject(new Error('aborted')); }, { once: true }));
    } });
    const stopped = assert.rejects(running);
    await blocked;
    await assert.rejects(collect(configPath, output, { probe: () => assert.fail('An overlapping run must not start a VPN') }));
    controller.abort();
    await assert.rejects(collect(configPath, output, { probe: () => assert.fail('Cancellation must hold the lock through cleanup') }));
    finishCleanup();
    await stopped;
    assert.equal(await readFile(output, 'utf8'), preserved);
    const expired = structuredClone(previous);
    expired.metadata.expires_at_unix = now - 1;
    expired.metadata.updated_at_unix = now - 600;
    expired.metadata.fetched_at_unix = now - 600;
    await writeFile(output, JSON.stringify(expired));
    assert.equal((await collect(configPath, output, { probe: measured })).refreshed, 2);
    assert.deepEqual(JSON.parse(await readFile(output)).entries.map(entry => entry.ip), ['8.8.4.4', '8.8.4.4']);
    await writeFile(output, '{invalid');
    await assert.rejects(collect(configPath, output, { probe: () => assert.fail('Invalid baseline must be preserved') }));
    assert.equal(await readFile(output, 'utf8'), '{invalid');

    for (const profile of config.profiles) {
        const calls = [];
        const statuses = ['starting', 'healthy', 'healthy'];
        const run = async (args, signal) => {
            calls.push(args);
            if (args[0] === 'inspect') { assert(signal); return { stdout: statuses.shift() }; }
            if (args.includes('openfingerprint-vpn-observer:local')) return { stdout: JSON.stringify(await measured(profile)) };
            return { stdout: args[0] === 'ps' ? '' : 'container' };
        };
        await measure(profile, config, 'test-vpn', { run, pause: async () => {} });
        const tunnel = calls.find(args => args.includes('--detach'));
        assert(tunnel.includes('FIREWALL=on') && tunnel.includes('--cap-add=NET_ADMIN'));
        assert(!tunnel.includes('--privileged') && !tunnel.includes('host'));
        assert(!tunnel.includes('test secret'));
        if (profile.type === 'openvpn') assert(tunnel.some(arg => arg.includes('/run/secrets/openvpn_password,readonly')));
        else assert(tunnel.includes('WIREGUARD_IMPLEMENTATION=userspace'));
        const probe = calls.find(args => args.includes('openfingerprint-vpn-observer:local'));
        assert.equal(probe[probe.indexOf('--network') + 1], 'container:test-vpn');
        assert(probe.includes('--read-only') && probe.includes('--cap-drop=ALL'));
        assert.deepEqual(calls.at(-2), ['rm', '--force', 'test-vpn-observer', 'test-vpn']);
        assert.equal(calls.at(-1)[0], 'ps');
    }
    for (const scenario of ['never-ready', 'lost-health', 'probe-error']) {
        const calls = [];
        let checks = 0;
        await assert.rejects(measure(config.profiles[0], config, 'failed-vpn', { pause: async () => {}, run: async args => {
            calls.push(args);
            if (args[0] === 'inspect') return { stdout: scenario === 'never-ready' || (scenario === 'lost-health' && checks++ > 0) ? 'unhealthy' : 'healthy' };
            if (args.includes('openfingerprint-vpn-observer:local')) {
                if (scenario === 'probe-error') throw new Error('echo failed');
                return { stdout: JSON.stringify(await measured(config.profiles[0])) };
            }
            return { stdout: '' };
        } }));
        if (scenario === 'never-ready') assert(!calls.some(args => args.includes('openfingerprint-vpn-observer:local')));
        assert.deepEqual(calls.at(-2), ['rm', '--force', 'failed-vpn-observer', 'failed-vpn']);
        assert.equal(calls.at(-1)[0], 'ps');
    }
    let cleanupChecks = 0;
    await assert.rejects(measure(config.profiles[0], config, 'cleanup-failure', { run: async args => {
        if (args[0] === 'ps') return { stdout: cleanupChecks++ === 0 ? '' : 'leftover-container' };
        if (args[0] === 'inspect') return { stdout: 'healthy' };
        if (args.includes('openfingerprint-vpn-observer:local')) return { stdout: JSON.stringify(await measured(config.profiles[0])) };
        return { stdout: '' };
    } }), { code: 'VPN_CLEANUP_FAILED' });
    await writeFile(output, preserved);
    await assert.rejects(collect(configPath, output, { probe: async () => {
        throw Object.assign(new Error('cleanup failed'), { code: 'VPN_CLEANUP_FAILED' });
    } }), { code: 'VPN_CLEANUP_FAILED' });
    assert.equal(await readFile(output, 'utf8'), preserved);
    if (process.argv.includes('--docker')) {
        const execute = promisify(execFile);
        const runDocker = (args, signal) => execute('docker', args, { signal, timeout: 45000, maxBuffer: 65536 });
        const liveConfig = { ...config, endpoint: 'https://api.ipify.org?format=json' };
        const baseline = await fetch(liveConfig.endpoint, { signal: AbortSignal.timeout(15000) });
        assert.equal(baseline.status, 200, 'The echo service must be reachable outside the dead tunnel');
        await baseline.body.cancel();
        const wireguard = resolve(directory, 'dead-tunnel.conf');
        await writeFile(wireguard, `[Interface]\nPrivateKey = ${randomBytes(32).toString('base64')}\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = ${randomBytes(32).toString('base64')}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n`, { mode: 0o600 });
        const profile = { id: 'dead-tunnel', provider: 'Test VPN', type: 'wireguard', config: wireguard };
        for (const bypassHealthGate of [false, true]) {
            let attempted = false;
            let escaped = false;
            const name = 'ofp-vpn-check-' + randomBytes(6).toString('hex');
            await assert.rejects(measure(profile, liveConfig, name, { signal: AbortSignal.timeout(20000), run: async (args, signal) => {
                if (bypassHealthGate && args[0] === 'inspect') {
                    const { stdout } = await runDocker(['logs', name], signal);
                    return { stdout: stdout.includes('[firewall] enabled successfully') ? 'healthy' : 'starting' };
                }
                if (args.includes('openfingerprint-vpn-observer:local')) {
                    attempted = true;
                    const result = await runDocker(args, signal);
                    escaped = true;
                    return result;
                }
                return runDocker(args, signal);
            } }));
            assert.equal(attempted, bypassHealthGate, 'Only the explicit firewall test bypasses the unhealthy gate');
            assert.equal(escaped, false, 'An unreachable tunnel must never fall back to host egress');
            assert.equal((await runDocker(['ps', '--all', '--quiet', '--filter', `name=^/${name}(-observer)?$`])).stdout.trim(), '');
        }
        console.log('Docker dead-tunnel smoke checks: unhealthy gating, fail-closed egress and cleanup passed.');
    }
    console.log('Scheduled VPN collection: isolation, health gates, secret mounts, cleanup, locking, partial failure, expiry and atomic preservation passed.');
} finally { await rm(directory, { recursive: true, force: true }); }
