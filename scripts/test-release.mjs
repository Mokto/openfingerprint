import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const json = async (path) => JSON.parse(await read(path));
const config = await json('release-please-config.json');
const manifest = await json('.release-please-manifest.json');
const root = await json('package.json');
const sdk = await json('sdk/package.json');
const api = await read('api/Cargo.toml');
const workflow = await read('.github/workflows/release-please.yml');
const publish = await read('.github/workflows/sdk-publish.yml');

assert.equal(root.private, true);
assert.equal(sdk.name, '@openfingerprint/sdk');
assert(!sdk.private);
assert.deepEqual(Object.keys(config.packages).sort(), ['api', 'sdk']);
assert.deepEqual(Object.keys(manifest).sort(), ['api', 'sdk']);
assert.equal(manifest.sdk, sdk.version);
assert.equal(manifest.api, /^version = "([^"]+)"$/m.exec(api)?.[1]);
for (const [path, type] of [['sdk', 'node'], ['api', 'rust']]) {
	const release = config.packages[path];
	assert.equal(release['release-type'], type);
	assert.equal(release.component, path);
	assert.equal(release['include-component-in-tag'], true);
	assert.equal(release['bump-minor-pre-major'], true);
	assert((await read(`${path}/CHANGELOG.md`)).includes(`## [${manifest[path]}]`));
	assert(workflow.includes(`if: steps.release.outputs['${path}--release_created'] == 'true'`));
	assert(workflow.includes(`steps.release.outputs['${path}--tag_name']`));
}
assert(!workflow.includes('steps.release.outputs.release_created'));
assert(!workflow.includes('steps.release.outputs.tag_name'));
assert(publish.includes("require('./sdk/package.json')"));
assert.match(publish, /working-directory: sdk\n\s+run: \|\n\s+npm pack/);
assert.match(publish, /working-directory: sdk\n\s+run: npm publish/);
assert.equal(await read('sdk/LICENSE'), await read('LICENSE'));
console.log('Release configuration, versions and publishing paths agree.');
