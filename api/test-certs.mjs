import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

/** A self-signed certificate in `dir` (tls.crt, tls.key), as the identify listener reads it. */
export function certificate(dir, name = 'localhost', ec = true) {
	mkdirSync(dir, { recursive: true });
	const key = join(dir, 'tls.key');
	if (ec) execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', key]);
	else execFileSync('openssl', ['genrsa', '-out', key, '2048'], { stdio: 'ignore' });
	execFileSync('openssl', ['req', '-new', '-x509', '-key', key, '-subj', `/CN=${name}`, '-days', '2', '-out', join(dir, 'tls.crt')]);
	// Test keys only: readable by the container's non-root user through a read-only mount.
	chmodSync(key, 0o644);
	chmodSync(dir, 0o755);
	return dir;
}

/** The variables the API needs to start, with a certificate under `directory`. */
export function identifyEnvironment(directory, { address = '127.0.0.1:0', certs } = {}) {
	return {
		OPENFINGERPRINT_IDENTIFY_ADDR: address,
		OPENFINGERPRINT_IDENTIFY_CERTS: certs ?? certificate(join(directory, 'identify-certs')),
		OPENFINGERPRINT_IDENTIFY_ORIGINS: 'https://app.example.test'
	};
}
