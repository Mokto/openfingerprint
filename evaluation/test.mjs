import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capture, validateSample } from './record.mjs';
import { analyze, validatePlan } from './analyze.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const study = randomUUID(), build = hash('test-build');
const deviceA = randomUUID(), deviceB = randomUUID(), deviceC = randomUUID();
const target = (device, cohort = 'real_device', family = 'chrome') => ({ browser: randomUUID(), device, cohort, family, platform: 'linux', deviceClass: 'desktop' });
const targets = [target(deviceA), target(deviceA, 'real_device', 'firefox'), target(deviceB), target(deviceC, 'synthetic')];
const plan = { format: 1, study, build, schema: 5, targets, rounds: [
    { id: 1, day: 0, condition: 'baseline' }, { id: 2, day: 0, condition: 'reload' }, { id: 3, day: 7, condition: 'return' }
] };
const metadata = (index, round) => ({ study, build, browser: targets[index].browser, round, consent: true });
const sdkResult = (full, core = full) => ({ version: 5, fingerprint: full === null ? null : hash(full), coreFingerprint: core === null ? null : hash(core),
    components: { canvas: hash('component') }, hints: {}, excluded: [], unavailable: {},
    storageId: 'private-secret', automation: { private: 'private-secret' }, extra: 'private-secret' });
const sample = (index, round, full, core = full) => capture(metadata(index, round), async () => sdkResult(full, core));
const rows = await Promise.all([
    sample(0, 1, 'a', 'core-a'), sample(0, 2, 'b', 'core-a'), sample(0, 3, null),
    sample(1, 1, 'b', 'core-a'), sample(1, 2, 'b', 'core-a'),
    sample(2, 1, 'c', 'core-b'), sample(2, 2, 'a', 'core-a'),
    capture(metadata(2, 3), async () => { throw new Error('private-secret'); }), sample(3, 1, 'a', 'core-a')
]);
const report = analyze(plan, rows, 3);
const real = report.cohorts.find(group => group.cohort === 'real_device');
assert.equal(report.real_device_observations, 8);
assert.equal(real.devices, 2);
assert.equal(real.browsers, 3);
assert.equal(real.expected_samples, 9);
assert.equal(real.recorded_samples, 8);
assert.equal(real.unrecorded_samples, 1);
assert.equal(real.failed_samples, 1);
assert.deepEqual(real.full.false_merges, { colliding_device_pairs: 1, compared_device_pairs: 1, enrolled_device_pairs: 1, pair_coverage: 1, rate: 1 });
assert.equal(real.full.returns.recorded, 5);
assert.equal(real.full.returns.matched, 1);
assert.equal(real.full.returns.missed, 4);
assert.equal(real.full.returns.missed_rate, 4 / 5);
assert.equal(real.full.returns.hash_churn_rate, 2 / 3);
assert.equal(real.full.returns.unrecorded, 1);
assert.equal(real.full.returns.planned_match_coverage, 1 / 6);
assert.equal(real.core.returns.matched, 2);
assert.equal(real.core.returns.hash_churn_rate, 1 / 3);
assert.equal(real.rounds[2].full_returns.missed_rate, 1);
assert.equal(real.strata.length, 2);
const synthetic = report.cohorts.find(group => group.cohort === 'synthetic');
assert.equal(synthetic.full.false_merges.rate, null);
assert.equal(synthetic.full.returns.missed_rate, null);
const baseline = analyze(plan, rows, 1).cohorts[0];
assert.equal(baseline.recorded_samples, 3);
assert.equal(baseline.full.false_merges.rate, 0);
assert.equal(baseline.full.returns.missed_rate, null);
assert.equal(baseline.unrecorded_samples, 0);
const repeatedCollision = structuredClone(rows);
repeatedCollision[7] = await sample(2, 3, 'b', 'core-a');
assert.equal(analyze(plan, repeatedCollision, 3).cohorts[0].full.false_merges.colliding_device_pairs, 1);
const extra = target(randomUUID());
const incompletePlan = { ...plan, targets: [...targets, extra] };
const incomplete = analyze(incompletePlan, rows, 3).cohorts[0];
assert.equal(incomplete.full.false_merges.compared_device_pairs, 1);
assert.equal(incomplete.full.false_merges.enrolled_device_pairs, 3);
assert.equal(incomplete.full.false_merges.pair_coverage, 1 / 3);
const withThirdDevice = [...rows, await capture({ ...metadata(0, 1), browser: extra.browser }, async () => sdkResult('a'))];
assert.equal(analyze(incompletePlan, withThirdDevice, 3).cohorts[0].full.false_merges.colliding_device_pairs, 3);
const regressedClock = structuredClone(rows);
regressedClock[1].at = new Date(Date.parse(rows[0].at) - 1000).toISOString();
assert.equal(analyze(plan, regressedClock, 3).cohorts[0].rounds[1].client_elapsed_days.clock_regressions, 1);
const empty = analyze(plan, [], 3).cohorts[0];
assert.equal(empty.full.false_merges.rate, null);
assert.equal(empty.full.returns.missed_rate, null);
assert.equal(empty.unrecorded_samples, 9);
const missingBaseline = structuredClone(rows);
missingBaseline[0].fingerprint = null;
const missing = analyze(plan, missingBaseline, 3).cohorts[0].full.returns;
assert.equal(missing.missing_baseline, 2);
assert.equal(missing.missed, 4);
assert.equal(missing.hash_churn_rate, 1 / 2);
let calls = 0;
await assert.rejects(capture({ ...metadata(0, 1), consent: false }, () => { calls++; }), /consent/);
await assert.rejects(capture({ ...metadata(0, 1), browser: [targets[0].browser] }, () => { calls++; }));
assert.equal(calls, 0);
for (const malformed of [{ ...sdkResult('a'), components: { canvas: 'private-secret' } }, { ...sdkResult('a'), unavailable: null }, { ...sdkResult('a'), version: 4 }]) {
    const result = await capture(metadata(0, 1), async () => malformed);
    assert.equal(result.status, 'failed');
    assert(!JSON.stringify(result).includes('private-secret'));
}
const excluded = await capture(metadata(0, 1), async () => ({ ...sdkResult('a'), components: { fonts: hash('font'), canvas: hash('diagnostic') },
    excluded: ['canvas', 'audio'], unavailable: { audio: 'timeout', gpu: 'unsupported' } }));
assert.deepEqual(excluded.includedComponents, ['fonts']);
const availability = analyze(plan, [excluded], 1).cohorts[0].unavailable_probes;
assert.deepEqual(availability, { identity: { 'gpu:unsupported': 1 }, diagnostic: { 'audio:timeout': 1 } });
assert(!JSON.stringify(rows).includes('private-secret'));
assert(!JSON.stringify(rows).includes(hash('component')));
for (const value of [study, ...targets.map(target => target.browser), deviceA, deviceB, hash('a'), hash('core-a')]) assert(!JSON.stringify(report).includes(value));
for (const invalid of [
    { ...rows[0], extra: true }, { ...rows[0], schema: 4 }, { ...rows[0], fingerprint: '' },
    { ...rows[0], at: '2026-02-31T00:00:00.000Z' }, { ...rows[0], includedComponents: [] },
    { ...rows[0], unavailable: { canvas: 'timeout' } }, { ...rows[0], status: 'failed' }
]) assert.throws(() => validateSample(invalid));
assert.throws(() => analyze(plan, [...rows, rows[0]], 3), /Duplicate/);
assert.throws(() => analyze(plan, [{ ...rows[0], build: hash('other-build') }], 3), /study/);
assert.throws(() => analyze(plan, [{ ...rows[0], browser: randomUUID() }], 3), /study/);
assert.throws(() => analyze(plan, rows, 4));
assert.throws(() => validatePlan({ ...plan, targets: [...targets, targets[0]] }));
assert.throws(() => validatePlan({ ...plan, schema: 4 }));
assert.throws(() => validatePlan({ ...plan, targets: [...targets.slice(0, 3), { ...targets[3], device: deviceA }] }));

const directory = await mkdtemp(join(tmpdir(), 'openfingerprint-evaluation-'));
try {
    const planFile = join(directory, 'plan.json'), sampleFile = join(directory, 'samples.jsonl');
    await writeFile(planFile, JSON.stringify(plan));
    await writeFile(sampleFile, rows.map(row => JSON.stringify(row)).join('\n') + '\n');
    const run = () => spawnSync(process.execPath, [fileURLToPath(new URL('./analyze.mjs', import.meta.url)), '--plan', planFile, '--samples', sampleFile, '--through-round', '3'], { encoding: 'utf8' });
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), report);
    await writeFile(sampleFile, JSON.stringify({ private: 'private-secret' }) + '\n');
    result = run();
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr.trim(), 'Invalid sample at line 1');
    assert(!result.stderr.includes('private-secret'));
} finally { await rm(directory, { recursive: true, force: true }); }
console.log('Identification evaluation: collision pairs, fixed-baseline returns, missingness, cohort isolation, consent and redaction checks passed.');
