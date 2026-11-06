import { environment } from './environment';
import { identityExclusions } from './policy';

const unsupported = Symbol();
const unstable = Symbol();
type Value = string | Uint8Array | typeof unsupported | typeof unstable;
type Status = 'unsupported' | 'unstable' | 'timeout' | 'error';

const fonts = [
	'Arial',
	'Arial Black',
	'Arial Narrow',
	'Calibri',
	'Cambria',
	'Candara',
	'Comic Sans MS',
	'Consolas',
	'Courier New',
	'DejaVu Sans',
	'Garamond',
	'Georgia',
	'Helvetica Neue',
	'Liberation Sans',
	'Menlo',
	'Monaco',
	'Noto Sans',
	'Palatino',
	'Roboto',
	'Segoe UI',
	'Tahoma',
	'Times New Roman',
	'Trebuchet MS',
	'Ubuntu',
	'Verdana',
	'American Typewriter',
	'Andale Mono',
	'Arial Rounded MT Bold',
	'Baskerville',
	'Bodoni 72',
	'Book Antiqua',
	'Bookman Old Style',
	'Bradley Hand',
	'Brush Script MT',
	'Calibri Light',
	'Calisto MT',
	'Chalkboard',
	'Chalkduster',
	'Copperplate',
	'Didot',
	'DIN Alternate',
	'DIN Condensed',
	'Futura',
	'Geneva',
	'Gill Sans',
	'Helvetica',
	'Herculanum',
	'Hoefler Text',
	'Impact',
	'Kefa',
	'Lucida Console',
	'Lucida Grande',
	'Luminari',
	'Marker Felt',
	'Microsoft Sans Serif',
	'Noteworthy',
	'Optima',
	'Papyrus',
	'Rockwell',
	'Savoye LET',
	'Segoe Print',
	'Segoe Script',
	'Snell Roundhand',
	'Times',
	'Trattatello',
	'Wingdings',
	'Zapfino',
	'Cantarell',
	'Carlito',
	'Droid Sans',
	'FreeMono',
	'FreeSans',
	'FreeSerif',
	'Liberation Mono',
	'Liberation Serif',
	'Noto Serif',
	'Ubuntu Mono',
	'Fira Code',
	'Fira Sans',
	'Inconsolata',
	'Inter',
	'Lato',
	'Montserrat',
	'Open Sans',
	'Roboto Mono',
	'Source Code Pro',
	'Source Sans Pro',
	'Yu Gothic',
	'Meiryo',
	'MS Gothic',
	'Malgun Gothic',
	'SimSun',
	'SimHei',
	'PingFang SC',
	'Hiragino Sans',
	'Noto Sans CJK JP'
];

function same(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && a.every((value, i) => value === b[i]);
}

async function hash(value: string | Uint8Array): Promise<string> {
	const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
	const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
	return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function canvas(): Value {
	const draw = (): Uint8Array | null => {
		const el = document.createElement('canvas');
		el.width = 240;
		el.height = 64;
		const ctx = el.getContext('2d', { willReadFrequently: true });
		if (!ctx) return null;
		const gradient = ctx.createLinearGradient(0, 0, 240, 64);
		gradient.addColorStop(0, '#193c75');
		gradient.addColorStop(1, '#f7b25e');
		ctx.fillStyle = gradient;
		ctx.fillRect(0, 0, 240, 64);
		ctx.fillStyle = 'rgba(30, 170, 120, 0.7)';
		ctx.beginPath();
		ctx.ellipse(121, 31, 87, 21, 0.23, 0, Math.PI * 2);
		ctx.fill();
		ctx.font = '19px serif';
		ctx.fillStyle = '#23172e';
		ctx.fillText('Trial: Aa 012345 / Ω', 11, 39);
		return new Uint8Array(ctx.getImageData(0, 0, 240, 64).data.buffer);
	};
	const a = draw(),
		b = draw();
	if (!a || !b) return unsupported;
	return same(a, b) ? a : unstable;
}

async function fontDocument(
	read: (ctx: CanvasRenderingContext2D, pause: () => Promise<boolean>) => Value | Promise<Value>,
	signal: AbortSignal,
	deadline: number
): Promise<Value> {
	// A separate document excludes the customer's @font-face definitions.
	const frame = document.createElement('iframe');
	frame.title = 'Fraud-prevention font probe';
	frame.setAttribute('aria-hidden', 'true');
	frame.tabIndex = -1;
	frame.hidden = true;
	frame.width = frame.height = '0';
	const channel = new MessageChannel();
	let resume: (() => void) | undefined;
	let sliceStart = -Infinity;
	const stop = () => {
		frame.remove();
		resume?.();
	};
	channel.port1.onmessage = () => {
		resume?.();
		resume = undefined;
	};
	const pause = async () => {
		if (signal.aborted || performance.now() >= deadline) return false;
		if (performance.now() - sliceStart >= 4) {
			await new Promise<void>((resolve) => {
				resume = resolve;
				channel.port2.postMessage(null);
			});
			sliceStart = performance.now();
		}
		return !signal.aborted && performance.now() < deadline;
	};
	signal.addEventListener('abort', stop, { once: true });
	try {
		document.documentElement.append(frame);
		const ctx = frame.contentDocument?.createElement('canvas').getContext('2d');
		if (!ctx) return unsupported;
		return await read(ctx, pause);
	} finally {
		frame.remove();
		signal.removeEventListener('abort', stop);
		channel.port1.close();
		channel.port2.close();
	}
}

function fontMetrics(signal: AbortSignal, deadline: number): Promise<Value> {
	return fontDocument(async (ctx, pause) => {
		const measure = (font: string) => {
			ctx.font = `64px ${font}`;
			return ctx.measureText('WWmm 0123456789 Il');
		};
		const bases = ['monospace', 'sans-serif', 'serif'];
		const widths: number[] = [];
		for (const base of bases) {
			if (!(await pause())) return unsupported;
			widths.push(measure(base).width);
		}
		const found: [string, number, number, number][] = [];
		for (const font of fonts) {
			for (let i = 0; i < bases.length; i++) {
				if (!(await pause())) return unsupported;
				const metric = measure(`"${font}",${bases[i]}`);
				if (metric.width !== widths[i]) {
					found.push([
						font,
						metric.width,
						metric.actualBoundingBoxAscent,
						metric.actualBoundingBoxDescent
					]);
					break;
				}
			}
		}
		return found.length ? JSON.stringify(found) : unsupported;
	}, signal, deadline);
}

function fontFallbacks(signal: AbortSignal, deadline: number): Promise<Value> {
	return fontDocument(async (ctx, pause) => {
		const values: number[][][] = [];
		for (const family of ['serif', 'sans-serif', 'monospace', 'system-ui', 'cursive', 'fantasy']) {
			const sizes: number[][] = [];
			for (const size of [12, 64]) {
				if (!(await pause())) return unsupported;
				ctx.font = `${size}px ${family}`;
				const metric = ctx.measureText('Aa fi Ω 012345 WWW iii');
				sizes.push([metric.width, metric.actualBoundingBoxAscent, metric.actualBoundingBoxDescent]);
			}
			values.push(sizes);
		}
		return JSON.stringify(values);
	}, signal, deadline);
}

async function fontPreferences(signal: AbortSignal): Promise<Value> {
	if (signal.aborted) return unsupported;
	const frame = document.createElement('iframe');
	frame.title = 'Fraud-prevention font preferences';
	frame.setAttribute('aria-hidden', 'true');
	frame.tabIndex = -1;
	for (const [name, value] of Object.entries({
		display: 'block',
		width: '300px',
		height: '150px',
		position: 'absolute',
		top: '0',
		left: '0',
		visibility: 'hidden',
		border: '0',
		'pointer-events': 'none'
	}))
		frame.style.setProperty(name, value, 'important');
	let cancel = () => {};
	const loaded = new Promise<boolean>((resolve, reject) => {
		frame.onload = () => resolve(true);
		frame.onerror = () => reject(new Error('Font frame failed'));
		cancel = () => {
			frame.remove();
			resolve(false);
		};
	});
	signal.addEventListener('abort', cancel, { once: true });
	try {
		frame.srcdoc =
			'<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body></body></html>';
		document.documentElement.append(frame);
		if (!(await loaded) || signal.aborted) return unsupported;
		const doc = frame.contentDocument,
			view = frame.contentWindow;
		if (!doc?.body || !view) return unsupported;
		const body = doc.body;
		// Android applies accessibility font sizes only to wide, in-flow text in a laid-out document.
		body.style.width = '4000px';
		body.style.setProperty('text-size-adjust', 'none');
		body.style.setProperty('-webkit-text-size-adjust', 'none');
		const chromium = /(?:Chrome|Chromium)\/(\d+)/.exec(navigator.userAgent);
		const ratio = view.devicePixelRatio;
		if (chromium) {
			if (!Number.isFinite(ratio) || ratio <= 0) return unsupported;
			body.style.zoom = String(1 / ratio);
		} else if (CSS.supports('zoom', 'reset')) body.style.zoom = 'reset';
		const text = doc.createElement('div');
		text.textContent = 'word '.repeat(200).trim();
		body.append(text);
		const presets = {
			default: {},
			apple: { font: '-apple-system-body' },
			serif: { fontFamily: 'serif' },
			sans: { fontFamily: 'sans-serif' },
			mono: { fontFamily: 'monospace' },
			min: { fontSize: '1px' },
			system: { fontFamily: 'system-ui' }
		};
		const elements = Object.entries(presets).map(([name, style]) => {
			const span = doc.createElement('span');
			span.textContent = 'mmMwWLliI0fiflO&1';
			span.style.whiteSpace = 'nowrap';
			Object.assign(span.style, style);
			body.append(doc.createElement('br'), span);
			return [name, span] as const;
		});
		const read = () =>
			Object.fromEntries(
				elements.map(([name, span]) => {
					let width = span.getBoundingClientRect().width;
					// Chromium 128+ applies CSS zoom to bounding rectangles as well as layout.
					if (chromium && Number(chromium[1]) >= 128) {
						const scale = /Android/i.test(navigator.userAgent) ? 1 : 1000;
						width = Math.floor(width * ratio * scale) / scale;
					}
					return [name, width];
				})
			);
		const first = read();
		const values = Object.values(first);
		if (
			values.some((value) => !Number.isFinite(value) || value < 0) ||
			!values.some((value) => value > 0)
		)
			return unsupported;
		return JSON.stringify(first) === JSON.stringify(read()) ? JSON.stringify(first) : unstable;
	} finally {
		signal.removeEventListener('abort', cancel);
		frame.onload = frame.onerror = null;
		frame.remove();
	}
}

function gpu(): Value {
	const el = document.createElement('canvas');
	el.width = el.height = 1;
	const ctx = el.getContext('webgl', { antialias: false, depth: false, stencil: false });
	if (!ctx) return unsupported;
	try {
		const debug = ctx.getExtension('WEBGL_debug_renderer_info');
		const parameters = [
			ctx.MAX_TEXTURE_SIZE,
			ctx.MAX_CUBE_MAP_TEXTURE_SIZE,
			ctx.MAX_RENDERBUFFER_SIZE,
			ctx.MAX_VIEWPORT_DIMS,
			ctx.MAX_VERTEX_ATTRIBS,
			ctx.MAX_VERTEX_UNIFORM_VECTORS,
			ctx.MAX_FRAGMENT_UNIFORM_VECTORS,
			ctx.MAX_VARYING_VECTORS,
			ctx.MAX_VERTEX_TEXTURE_IMAGE_UNITS,
			ctx.MAX_TEXTURE_IMAGE_UNITS,
			ctx.MAX_COMBINED_TEXTURE_IMAGE_UNITS,
			ctx.ALIASED_LINE_WIDTH_RANGE,
			ctx.ALIASED_POINT_SIZE_RANGE,
			ctx.COMPRESSED_TEXTURE_FORMATS,
			ctx.RED_BITS,
			ctx.GREEN_BITS,
			ctx.BLUE_BITS,
			ctx.ALPHA_BITS,
			ctx.DEPTH_BITS,
			ctx.STENCIL_BITS,
			ctx.SUBPIXEL_BITS,
			ctx.SHADING_LANGUAGE_VERSION,
			ctx.VERSION
		].map((parameter) => {
			const value = ctx.getParameter(parameter);
			return ArrayBuffer.isView(value) ? Array.from(value as unknown as Iterable<number>) : value;
		});
		const precision = [ctx.VERTEX_SHADER, ctx.FRAGMENT_SHADER].map((shader) =>
			[
				ctx.LOW_FLOAT,
				ctx.MEDIUM_FLOAT,
				ctx.HIGH_FLOAT,
				ctx.LOW_INT,
				ctx.MEDIUM_INT,
				ctx.HIGH_INT
			].map((type) => {
				const p = ctx.getShaderPrecisionFormat(shader, type);
				return p ? [p.rangeMin, p.rangeMax, p.precision] : null;
			})
		);
		const anisotropy = ctx.getExtension('EXT_texture_filter_anisotropic');
		const buffers = ctx.getExtension('WEBGL_draw_buffers');
		return JSON.stringify([
			ctx.getParameter(ctx.VENDOR),
			ctx.getParameter(ctx.RENDERER),
			debug ? ctx.getParameter(debug.UNMASKED_VENDOR_WEBGL) : null,
			debug ? ctx.getParameter(debug.UNMASKED_RENDERER_WEBGL) : null,
			parameters,
			precision,
			anisotropy ? ctx.getParameter(anisotropy.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null,
			buffers
				? [
						ctx.getParameter(buffers.MAX_DRAW_BUFFERS_WEBGL),
						ctx.getParameter(buffers.MAX_COLOR_ATTACHMENTS_WEBGL)
					]
				: null,
			(ctx.getSupportedExtensions() || []).sort()
		]);
	} finally {
		ctx.getExtension('WEBGL_lose_context')?.loseContext();
	}
}

async function audio(signal: AbortSignal): Promise<Value> {
	const Offline =
		globalThis.OfflineAudioContext ||
		(
			globalThis as typeof globalThis & {
				webkitOfflineAudioContext?: typeof OfflineAudioContext;
			}
		).webkitOfflineAudioContext;
	if (!Offline) return unsupported;
	const render = async (): Promise<Uint8Array> => {
		const ctx = new Offline(1, 4096, 44100);
		const oscillator = ctx.createOscillator();
		let compressor: DynamicsCompressorNode | undefined;
		const cleanup = () => {
			oscillator.disconnect();
			compressor?.disconnect();
		};
		signal.addEventListener('abort', cleanup, { once: true });
		try {
			compressor = ctx.createDynamicsCompressor();
			oscillator.type = 'triangle';
			oscillator.frequency.value = 997;
			compressor.threshold.value = -37;
			compressor.knee.value = 23;
			compressor.ratio.value = 9;
			oscillator.connect(compressor);
			compressor.connect(ctx.destination);
			oscillator.start();
			const buffer = await ctx.startRendering();
			const samples = buffer.getChannelData(0);
			return new Uint8Array(samples.slice(2048).buffer);
		} finally {
			cleanup();
			signal.removeEventListener('abort', cleanup);
		}
	};
	const [a, b] = await Promise.all([render(), render()]);
	if (a.every((byte) => byte === 0) || b.every((byte) => byte === 0)) return unsupported;
	return same(a, b) ? a : unstable;
}

const probes = {
	audio,
	canvas,
	fonts: fontMetrics,
	fontFallbacks,
	fontPreferences,
	gpu,
	...environment
};

type Name = keyof typeof probes;
export interface Options {
	timeoutMs?: number;
	storageKey?: string;
	onIdentity?: (snapshot: Result) => unknown;
}
export interface Result {
	version: 5;
	excluded: Name[];
	fingerprint: string | null;
	coreFingerprint: string | null;
	components: Partial<Record<Name, string>>;
	hints: Partial<Record<Name, string>>;
	unavailable: Partial<Record<Name, Status>>;
	storageId: string | null;
	durationMs: number;
	timings: Partial<Record<Name, { durationMs: number; blockingMs: number }>>;
}

function storageId(key: string | undefined): string | null {
	if (!key) return null;
	try {
		const name = `stealth:${key}`;
		const saved = localStorage.getItem(name);
		if (saved && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(saved)) return saved;
		const id = crypto.randomUUID();
		localStorage.setItem(name, id);
		return id;
	} catch {
		return null;
	}
}

export async function collect(options: Options = {}): Promise<Result> {
	const { timeoutMs = 2000, storageKey, onIdentity } = options;
	if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000)
		throw new RangeError('timeoutMs must be between 1 and 5000');
	if (
		storageKey !== undefined &&
		(typeof storageKey !== 'string' || !storageKey.length || storageKey.length > 128)
	)
		throw new TypeError('storageKey must contain 1–128 characters');
	if (onIdentity !== undefined && typeof onIdentity !== 'function')
		throw new TypeError('onIdentity must be a function');
	if (typeof window === 'undefined' || !globalThis.crypto?.subtle)
		throw new Error('A secure browser context is required');
	const start = performance.now();
	const deadline = start + timeoutMs;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	const expired = () => {
		if (performance.now() >= deadline) controller.abort();
		return controller.signal.aborted;
	};
	const result: Result = {
		version: 5,
		excluded: identityExclusions(navigator.userAgent, navigator.vendor),
		fingerprint: null,
		coreFingerprint: null,
		components: {},
		hints: {},
		unavailable: {},
		storageId: null,
		durationMs: 0,
		timings: {}
	};
	const excluded = new Set(result.excluded);
	try {
		const run = async (name: Name) => {
			let began = performance.now(),
				blockingMs = 0;
			let onAbort: () => void = () => {};
			const timeout = new Promise<{ status: Status }>((resolve) => {
				onAbort = () => resolve({ status: 'timeout' });
				controller.signal.addEventListener('abort', onAbort, { once: true });
			});
			const work = Promise.resolve()
				.then(async (): Promise<{ hash: string } | { status: Status }> => {
					if (expired()) return { status: 'timeout' };
					began = performance.now();
					const pending = probes[name](controller.signal, deadline);
					blockingMs = performance.now() - began;
					const value = await pending;
					if (expired()) return { status: 'timeout' };
					if (value === unsupported) return { status: 'unsupported' };
					if (value === unstable) return { status: 'unstable' };
					const digest = await hash(value);
					return expired() ? { status: 'timeout' } : { hash: digest };
				})
				.catch((): { status: Status } => ({
					status: expired() ? 'timeout' : 'error'
				}));
			const done = await Promise.race([work, timeout]);
			controller.signal.removeEventListener('abort', onAbort);
			result.timings[name] = {
				durationMs: Math.round((performance.now() - began) * 10) / 10,
				blockingMs: Math.round(blockingMs * 10) / 10
			};
			if ('status' in done) result.unavailable[name] = done.status;
			else (name in environment ? result.hints : result.components)[name] = done.hash;
		};
		const audioJob = excluded.has('audio') ? null : run('audio');
		// Finish each cheap probe's hash before GPU initialization can block the
		// main thread past the deadline and discard those earlier observations.
		for (const name of Object.keys(probes) as Name[])
			if (name !== 'audio' && name !== 'gpu' && !excluded.has(name)) await run(name);
		await run('gpu');
		await audioJob;
		const entries = Object.entries(result.components)
			.filter(([name]) => !result.excluded.includes(name as Name))
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		if (entries.length && !expired()) {
			let onAbort: () => void = () => {};
			const timeout = new Promise<[null, null]>((resolve) => {
				onAbort = () => resolve([null, null]);
				controller.signal.addEventListener('abort', onAbort, { once: true });
			});
			const hints = Object.entries(result.hints)
				.filter(([name]) => !result.excluded.includes(name as Name))
				.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
			[result.fingerprint, result.coreFingerprint] = await Promise.race([
				Promise.all([
					hash(`stealth-agent:5\0${JSON.stringify({ components: entries, hints })}`).catch(
						() => null
					),
					hash(`stealth-core:5\0${JSON.stringify(entries)}`).catch(() => null)
				]),
				timeout
			]);
			controller.signal.removeEventListener('abort', onAbort);
		}
		result.storageId = storageId(storageKey);
		if (onIdentity) {
			const snapshot: Result = {
				...result,
				excluded: [...result.excluded],
				components: { ...result.components },
				hints: { ...result.hints },
				unavailable: { ...result.unavailable },
				timings: Object.fromEntries(
					Object.entries(result.timings).map(([name, timing]) => [name, { ...timing }])
				),
				durationMs: Math.round((performance.now() - start) * 10) / 10
			};
			try {
				void Promise.resolve(onIdentity(snapshot)).catch(() => {});
			} catch {}
		}
		// Diagnostic timeouts must not erase an already-computed identity.
		for (const name of result.excluded) if (name !== 'audio') await run(name);
		if (excluded.has('audio')) await run('audio');
		result.durationMs = Math.round((performance.now() - start) * 10) / 10;
		return result;
	} finally {
		controller.abort();
		clearTimeout(timer);
	}
}
