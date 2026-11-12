import { execFileSync } from 'node:child_process';

if (!process.env.OPENFINGERPRINT_TEST_POSTGRES_URL) {
    console.log('PostgreSQL visitor integration checks skipped: set OPENFINGERPRINT_TEST_POSTGRES_URL to a disposable database with sslmode=disable.');
} else {
    execFileSync('cargo', ['test', '--manifest-path', 'api/Cargo.toml', '--locked', 'visitor', '--', '--include-ignored'], { stdio: 'inherit' });
}
