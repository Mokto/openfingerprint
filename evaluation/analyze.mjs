import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { validateSample } from './record.mjs';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const conditions = ['baseline', 'reload', 'restart', 'private', 'browser_update', 'os_update', 'settings_change', 'return'];
const pairCount = count => count * (count - 1) / 2;
const rate = (count, total) => total ? count / total : null;
function keys(value, expected) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key));
}
export function validatePlan(plan) {
    assert(keys(plan, ['format', 'study', 'build', 'schema', 'targets', 'rounds']), 'Invalid study plan fields');
    assert(plan.format === 1 && plan.schema === 5 && typeof plan.study === 'string' && uuid.test(plan.study)
        && typeof plan.build === 'string' && /^[0-9a-f]{64}$/.test(plan.build), 'Invalid study identity or SDK build');
    // ponytail: 500 targets bound the O(n²) distinct collision-pair set; use bitsets or external aggregation for larger cohorts.
    assert(Array.isArray(plan.targets) && plan.targets.length > 0 && plan.targets.length <= 500, 'A study requires 1–500 browser targets');
    assert(Array.isArray(plan.rounds) && plan.rounds.length > 0 && plan.rounds.length <= 32, 'A study requires 1–32 rounds');
    const browsers = new Set();
    const devices = new Map();
    for (const target of plan.targets) {
        assert(keys(target, ['browser', 'device', 'cohort', 'platform', 'family', 'deviceClass']), 'Invalid target fields');
        assert(typeof target.browser === 'string' && uuid.test(target.browser) && typeof target.device === 'string' && uuid.test(target.device) && !browsers.has(target.browser), 'Invalid or duplicate target label');
        assert(['real_device', 'synthetic'].includes(target.cohort)
            && ['windows', 'macos', 'linux', 'ios', 'android', 'other'].includes(target.platform)
            && ['chrome', 'chromium', 'firefox', 'safari', 'edge', 'webkit', 'other'].includes(target.family)
            && ['desktop', 'phone', 'tablet', 'other'].includes(target.deviceClass), 'Invalid target classification');
        const device = JSON.stringify([target.cohort, target.deviceClass]);
        assert(!devices.has(target.device) || devices.get(target.device) === device, 'Inconsistent device classification');
        devices.set(target.device, device);
        browsers.add(target.browser);
    }
    for (const [index, round] of plan.rounds.entries()) {
        assert(keys(round, ['id', 'day', 'condition']) && round.id === index + 1
            && Number.isInteger(round.day) && round.day >= 0 && round.day <= 365
            && conditions.includes(round.condition), 'Invalid planned round');
        assert(index ? round.day >= plan.rounds[index - 1].day : round.day === 0 && round.condition === 'baseline', 'Invalid round schedule');
    }
    return plan;
}
function returns(targets, rounds, samples, field) {
    const result = { planned: targets.length * rounds.length, recorded: 0, matched: 0, comparable: 0, changed: 0, missing_baseline: 0, missing_current: 0 };
    for (const target of targets) {
        const baseline = samples.get(`${target.browser}:1`)?.[field] ?? null;
        for (const round of rounds) {
            const sample = samples.get(`${target.browser}:${round.id}`);
            if (!sample) continue;
            const current = sample[field];
            result.recorded++;
            if (baseline === null) result.missing_baseline++;
            if (current === null) result.missing_current++;
            if (baseline !== null && current !== null) {
                result.comparable++;
                if (baseline === current) result.matched++;
                else result.changed++;
            }
        }
    }
    return { ...result, unrecorded: result.planned - result.recorded,
        missed: result.recorded - result.matched, missed_rate: rate(result.recorded - result.matched, result.recorded),
        hash_churn_rate: rate(result.changed, result.comparable), planned_match_coverage: rate(result.matched, result.planned) };
}
function measure(targets, rounds, rows) {
    const samples = new Map(rows.map(row => [`${row.browser}:${row.round}`, row]));
    const labels = new Map(targets.map(target => [target.browser, target.device]));
    const deviceCount = new Set(labels.values()).size;
    const strategy = field => {
        const present = rows.filter(row => row[field] !== null);
        const observedDevices = new Set(present.map(row => labels.get(row.browser)));
        const collisions = new Set();
        for (const bucket of Map.groupBy(present, row => row[field]).values()) {
            const devices = [...new Set(bucket.map(row => labels.get(row.browser)))].sort();
            for (let i = 0; i < devices.length; i++) {
                for (let j = i + 1; j < devices.length; j++) collisions.add(`${devices[i]}:${devices[j]}`);
            }
        }
        const compared = pairCount(observedDevices.size);
        return { present_ids: present.length, missing_ids: rows.length - present.length,
            false_merges: { colliding_device_pairs: collisions.size, compared_device_pairs: compared,
                enrolled_device_pairs: pairCount(deviceCount), pair_coverage: rate(compared, pairCount(deviceCount)),
                rate: rate(collisions.size, compared) },
            returns: returns(targets, rounds.slice(1), samples, field) };
    };
    const unavailable = { identity: {}, diagnostic: {} };
    for (const row of rows) for (const [name, status] of Object.entries(row.unavailable)) {
        const counts = unavailable[row.excluded.includes(name) ? 'diagnostic' : 'identity'];
        const key = `${name}:${status}`;
        counts[key] = (counts[key] ?? 0) + 1;
    }
    const roundRows = Map.groupBy(rows, row => row.round);
    const elapsed = round => {
        const days = (roundRows.get(round.id) ?? []).flatMap(row => {
            const baseline = samples.get(`${row.browser}:1`);
            return baseline ? [(Date.parse(row.at) - Date.parse(baseline.at)) / 86400000] : [];
        });
        return { min: days.length ? Math.min(...days) : null, max: days.length ? Math.max(...days) : null,
            clock_regressions: days.filter(day => day < 0).length };
    };
    return { devices: deviceCount, browsers: targets.length, expected_samples: targets.length * rounds.length,
        recorded_samples: rows.length, unrecorded_samples: targets.length * rounds.length - rows.length,
        failed_samples: rows.filter(row => row.status === 'failed').length, unavailable_probes: unavailable,
        full: strategy('fingerprint'), core: strategy('coreFingerprint'),
        rounds: rounds.map(round => ({ ...round, client_elapsed_days: elapsed(round), recorded_samples: roundRows.get(round.id)?.length ?? 0,
            unrecorded_samples: targets.length - (roundRows.get(round.id)?.length ?? 0),
            full_returns: returns(targets, round.id === 1 ? [] : [round], samples, 'fingerprint'),
            core_returns: returns(targets, round.id === 1 ? [] : [round], samples, 'coreFingerprint') })) };
}
export function analyze(plan, rows, throughRound) {
    validatePlan(plan);
    assert(Number.isInteger(throughRound) && throughRound >= 1 && throughRound <= plan.rounds.length, 'Choose a completed round from the plan');
    assert(Array.isArray(rows) && rows.length <= plan.targets.length * plan.rounds.length, 'Too many samples');
    const targets = new Map(plan.targets.map(target => [target.browser, target]));
    const seen = new Set();
    for (const row of rows) {
        validateSample(row);
        assert(row.study === plan.study && row.build === plan.build && targets.has(row.browser)
            && row.round <= plan.rounds.length, 'Sample does not match study plan');
        const key = `${row.browser}:${row.round}`;
        assert(!seen.has(key), 'Duplicate browser/round sample');
        seen.add(key);
    }
    const included = rows.filter(row => row.round <= throughRound);
    const rounds = plan.rounds.slice(0, throughRound);
    const cohorts = [];
    for (const [cohort, members] of Map.groupBy(plan.targets, target => target.cohort)) {
        const labels = new Set(members.map(target => target.browser));
        const observations = included.filter(row => labels.has(row.browser));
        const strata = [];
        for (const group of Map.groupBy(members, target => `${target.platform}/${target.family}/${target.deviceClass}`).values()) {
            const labels = new Set(group.map(target => target.browser));
            strata.push({ platform: group[0].platform, family: group[0].family, deviceClass: group[0].deviceClass,
                ...measure(group, rounds, observations.filter(row => labels.has(row.browser))) });
        }
        cohorts.push({ cohort, ...measure(members, rounds, observations), strata });
    }
    return { format: 1, schema: plan.schema, build: plan.build, through_round: throughRound,
        scope: 'Descriptive exact-hash measurements on externally labelled browser targets; not population accuracy or device attestation.',
        real_device_observations: included.filter(row => targets.get(row.browser).cohort === 'real_device').length,
        cohorts };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const { values } = parseArgs({ options: { plan: { type: 'string' }, samples: { type: 'string' }, 'through-round': { type: 'string' } } });
        assert(values.plan && values.samples && /^\d+$/.test(values['through-round'] ?? ''), 'Usage: node evaluation/analyze.mjs --plan PLAN --samples JSONL --through-round N');
        const planStat = await stat(values.plan), sampleStat = await stat(values.samples);
        assert(planStat.isFile() && sampleStat.isFile(), 'Study inputs must be regular files');
        assert(planStat.size <= 1024 * 1024, 'Study plan exceeds 1 MiB');
        assert(sampleStat.size <= 32 * 1024 * 1024, 'Sample file exceeds 32 MiB');
        let plan;
        try { plan = validatePlan(JSON.parse(await readFile(values.plan, 'utf8'))); }
        catch { throw new Error('Invalid study plan'); }
        const rows = [];
        const stream = createReadStream(values.samples, { encoding: 'utf8', end: 32 * 1024 * 1024 });
        const lines = createInterface({ input: stream, crlfDelay: Infinity });
        try {
            for await (const line of lines) {
                assert(Buffer.byteLength(line) <= 8192 && rows.length < plan.targets.length * plan.rounds.length, 'Sample input exceeds study bounds');
                try { rows.push(validateSample(JSON.parse(line))); }
                catch { throw new Error(`Invalid sample at line ${rows.length + 1}`); }
            }
            assert(stream.bytesRead <= 32 * 1024 * 1024, 'Sample file exceeds 32 MiB');
        } finally { lines.close(); stream.destroy(); }
        console.log(JSON.stringify(analyze(plan, rows, Number(values['through-round'])), null, 2));
    } catch (error) {
        const safe = ['Usage:', 'Study inputs must be', 'Study plan exceeds', 'Sample file exceeds', 'Invalid study plan', 'Invalid sample at line', 'Sample input exceeds', 'Sample does not match', 'Duplicate browser/round', 'Choose a completed round', 'Too many samples'];
        console.error(safe.some(prefix => error.message?.startsWith(prefix)) ? error.message : 'Evaluation failed; check the plan and sample files.');
        process.exitCode = 1;
    }
}
