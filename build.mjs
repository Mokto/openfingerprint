import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

await build({
	configFile: false,
	root: fileURLToPath(new URL('.', import.meta.url)),
	build: {
		target: 'es2022',
		minify: true,
		sourcemap: true,
		rolldownOptions: {
			output: {
				comments: { legal: true },
				banner: `/*!\n${await readFile(new URL('THIRD-PARTY-NOTICES', import.meta.url), 'utf8')}*/`
			}
		},
		lib: {
			entry: fileURLToPath(new URL('src/index.ts', import.meta.url)),
			formats: ['es', 'iife'],
			name: 'OpenFingerprint',
			fileName: (format) => (format === 'es' ? 'index.js' : 'index.iife.js')
		}
	}
});
