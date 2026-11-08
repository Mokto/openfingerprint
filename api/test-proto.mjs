import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'openfingerprint-proto-'));
const output = join(dir, 'fds.bin');
try {
    execFileSync('protoc', ['-I', 'api/proto', '--include_imports', `--descriptor_set_out=${output}`, 'api/proto/openfingerprint.proto'], { stdio: 'pipe' });
    assert(readFileSync(output).equals(readFileSync('api/proto/openfingerprint.fds.bin')),
        'api/proto/openfingerprint.fds.bin is stale: run the protoc command in api/build.rs');
    console.log('Committed protobuf descriptor set matches proto/openfingerprint.proto.');
} catch (error) {
    if (error.code !== 'ENOENT') throw error;
    console.log('Proto descriptor check skipped: install protoc to compare it with the committed descriptor set.');
} finally {
    rmSync(dir, { recursive: true });
}
