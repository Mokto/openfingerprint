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
				banner: (
					await Promise.all(
						['LICENSE', 'THIRD-PARTY-NOTICES'].map((name) => readFile(new URL(name, import.meta.url), 'utf8'))
					)
				)
					.map((notice) => `/*!\n${notice}*/`)
					.join('\n')
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
