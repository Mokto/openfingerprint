const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hash = /^[0-9a-f]{64}$/;
const components = ['audio', 'canvas', 'fontFallbacks', 'fontPreferences', 'fonts', 'gpu'];
const hints = ['platform', 'hardware', 'locale', 'display', 'screen', 'browser', 'features', 'media', 'math', 'architecture'];
const statuses = ['unsupported', 'unstable', 'timeout', 'error'];
const metadataKeys = ['study', 'build', 'browser', 'round', 'consent'];
const sampleKeys = [...metadataKeys, 'format', 'at', 'status', 'schema', 'fingerprint', 'coreFingerprint', 'includedComponents', 'includedHints', 'excluded', 'unavailable'];

function check(condition, message) {
    if (!condition) throw new Error(message);
}
function keys(value, expected) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key));
}
function metadata(value) {
    check(typeof value.study === 'string' && uuid.test(value.study) && typeof value.browser === 'string' && uuid.test(value.browser), 'Study and browser labels must be random UUIDs');
    check(typeof value.build === 'string' && hash.test(value.build), 'Invalid SDK build digest');
    check(Number.isInteger(value.round) && value.round >= 1 && value.round <= 32, 'Invalid visit round');
    check(value.consent === true, 'Explicit study consent is required');
}
function names(value, allowed) {
    return Array.isArray(value) && value.length <= allowed.length
        && new Set(value).size === value.length && value.every(name => allowed.includes(name));
}
export function validateSample(value) {
    check(keys(value, sampleKeys), 'Invalid sample fields');
    metadata(value);
    check(value.format === 1, 'Unsupported sample format');
    const time = typeof value.at === 'string' ? Date.parse(value.at) : NaN;
    check(Number.isFinite(time) && new Date(time).toISOString() === value.at, 'Invalid sample time');
    check(['collected', 'failed'].includes(value.status), 'Invalid collection status');
    check(value.schema === (value.status === 'collected' ? 1 : null), 'Unsupported identity schema');
    for (const field of ['fingerprint', 'coreFingerprint']) {
        check(value[field] === null || (typeof value[field] === 'string' && hash.test(value[field])), 'Invalid identity digest');
    }
    check(names(value.includedComponents, components) && names(value.includedHints, hints)
        && names(value.excluded, [...components, ...hints]), 'Invalid probe names');
    check(value.unavailable !== null && typeof value.unavailable === 'object' && !Array.isArray(value.unavailable)
        && Object.entries(value.unavailable).every(([name, status]) => [...components, ...hints].includes(name) && statuses.includes(status)), 'Invalid unavailable probes');
    check(![...value.includedComponents, ...value.includedHints].some(name => value.excluded.includes(name) || Object.hasOwn(value.unavailable, name)), 'Inconsistent probe availability');
    check(value.includedComponents.length > 0 || (value.fingerprint === null && value.coreFingerprint === null), 'Identity has no included components');
    if (value.status === 'failed') {
        check(value.fingerprint === null && value.coreFingerprint === null && value.includedComponents.length === 0
            && value.includedHints.length === 0 && value.excluded.length === 0 && Object.keys(value.unavailable).length === 0, 'Failed sample contains evidence');
    }
    return value;
}
export async function capture(value, collect) {
    check(keys(value, metadataKeys), 'Invalid capture metadata');
    metadata(value);
    check(typeof collect === 'function', 'A collector is required');
    const base = { ...value, format: 1, at: new Date().toISOString() };
    try {
        const result = await collect();
        check(result.version === 1 && Array.isArray(result.excluded), 'Unsupported SDK result');
        for (const map of [result.components, result.hints]) {
            check(map !== null && typeof map === 'object' && !Array.isArray(map)
                && Object.values(map).every(value => typeof value === 'string' && hash.test(value)), 'Invalid SDK probe hashes');
        }
        check(result.unavailable !== null && typeof result.unavailable === 'object' && !Array.isArray(result.unavailable), 'Invalid SDK availability');
        const excluded = [...result.excluded].sort();
        return validateSample({ ...base, status: 'collected', schema: result.version,
            fingerprint: result.fingerprint, coreFingerprint: result.coreFingerprint,
            includedComponents: Object.keys(result.components).filter(name => !excluded.includes(name)).sort(),
            includedHints: Object.keys(result.hints).filter(name => !excluded.includes(name)).sort(),
            excluded, unavailable: { ...result.unavailable } });
    } catch {
        return validateSample({ ...base, status: 'failed', schema: null, fingerprint: null, coreFingerprint: null,
            includedComponents: [], includedHints: [], excluded: [], unavailable: {} });
    }
}
