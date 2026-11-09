export interface AutomationEvidence {
	version: 3;
	webdriver: boolean | null;
	headlessUserAgent: boolean | null;
	seleniumArtifacts: boolean | null;
	phantomArtifacts: boolean | null;
	platformMismatch: boolean | null;
	missingChromeObject: boolean | null;
	notificationPermissionQuirk: boolean | null;
	emptyPlugins: boolean | null;
	emptyLanguages: boolean | null;
	softwareRenderer: boolean | null;
	zeroDimensions: boolean | null;
	cdpDetected: boolean | null;
	nativeFunctionTampering: boolean | null;
	workerUserAgentMismatch: boolean | null;
}

type AsyncKeys = 'notificationPermissionQuirk' | 'workerUserAgentMismatch';


function observe(read: () => unknown): boolean | null {
	try {
		const value = read();
		return typeof value === 'boolean' ? value : null;
	} catch {
		return null;
	}
}

function text(value: unknown): string | null {
	return typeof value === 'string' && value.length > 0 ? value : null;
}

function family(value: string): string | null {
	if (/iphone|ipad|ipod|\bios\b/i.test(value)) return 'ios';
	if (/windows|win32|win64/i.test(value)) return 'windows';
	if (/mac|darwin/i.test(value)) return 'mac';
	if (/linux|android|x11|cros|chrom(e|ium) os/i.test(value)) return 'linux';
	return null;
}

function chromium(userAgent: string): boolean {
	return /\bChrome\/\d/.test(userAgent) && !/; wv\)/.test(userAgent);
}

function desktop(userAgent: string): boolean {
	return !/Mobile|Android/.test(userAgent);
}

function platformMismatch(): boolean | null {
	const ua = text(navigator.userAgent);
	const platform = text(navigator.platform);
	if (!ua || !platform) return null;
	const expected = family(ua);
	const data = (navigator as { userAgentData?: { platform?: unknown } }).userAgentData?.platform;
	return [platform, text(data)].some((value) => {
		const actual = value && family(value);
		return !!expected && !!actual && actual !== expected;
	});
}

export function isSoftwareRenderer(renderer: unknown): boolean | null {
	const name = text(renderer);
	return name ? /swiftshader|llvmpipe|softpipe|software rasterizer|mesa offscreen/i.test(name) : null;
}

function cdpDetected(): boolean {
	let read = false;
	const error = new Error();
	Object.defineProperty(error, 'stack', {
		get() {
			read = true;
			return '';
		}
	});
	console.debug(error);
	return read;
}

// Error monitors such as Sentry replace Function.prototype.toString with a wrapper that still
// answers correctly, so its own source is not evidence of anything. The natives that automation
// tooling patches are read with the toString of a fresh same-origin frame instead, which page
// scripts have not touched. Without a frame the answer is unknown, never a guess.
function nativeFunctionTampering(): boolean | null {
	try {
		Function.prototype.toString.call({});
		return true;
	} catch (error) {
		if (!(error instanceof TypeError)) return true;
	}
	const parent = document.body ?? document.documentElement;
	if (!parent) return null;
	const frame = document.createElement('iframe');
	frame.style.display = 'none';
	frame.setAttribute('aria-hidden', 'true');
	frame.tabIndex = -1;
	parent.appendChild(frame);
	try {
		const untouched = (frame.contentWindow as (Window & typeof globalThis) | null)?.Function.prototype
			.toString;
		if (typeof untouched !== 'function') return null;
		const native = (fn: unknown) =>
			typeof fn === 'function' &&
			!('prototype' in fn) &&
			/\{\s*\[native code\]\s*\}\s*$/.test(untouched.call(fn));
		return ![
			Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')?.get,
			typeof Permissions === 'undefined' ? undefined : Permissions.prototype.query
		].every((fn) => fn === undefined || native(fn));
	} finally {
		frame.remove();
	}
}

function settle(work: () => Promise<boolean | null>, signal: AbortSignal): Promise<boolean | null> {
	return new Promise((resolve) => {
		const done = () => resolve(null);
		signal.addEventListener('abort', done, { once: true });
		if (signal.aborted) return done();
		try {
			work().then((value) => resolve(typeof value === 'boolean' ? value : null), done);
		} catch {
			done();
		}
	});
}

function notificationPermissionQuirk(): Promise<boolean | null> {
	if (typeof Notification === 'undefined' || Notification.permission !== 'denied')
		return Promise.resolve(false);
	return navigator.permissions
		.query({ name: 'notifications' })
		.then((status) => status.state === 'prompt');
}

function workerUserAgentMismatch(signal: AbortSignal): Promise<boolean | null> {
	const ua = text(navigator.userAgent);
	const platform = text(navigator.platform);
	if (!ua || !platform) return Promise.resolve(null);
	const url = URL.createObjectURL(
		new Blob(['postMessage([navigator.userAgent,navigator.platform])'], { type: 'text/javascript' })
	);
	return new Promise<boolean | null>((resolve, reject) => {
		let worker: Worker;
		try {
			worker = new Worker(url);
		} catch (error) {
			URL.revokeObjectURL(url);
			return reject(error);
		}
		const stop = () => {
			worker.terminate();
			URL.revokeObjectURL(url);
		};
		signal.addEventListener('abort', stop, { once: true });
		worker.onerror = (event) => {
			event.preventDefault();
			stop();
			reject(new Error('worker unavailable'));
		};
		worker.onmessage = (event) => {
			stop();
			const [workerUa, workerPlatform] = event.data ?? [];
			resolve(
				typeof workerUa === 'string' && typeof workerPlatform === 'string'
					? workerUa !== ua || workerPlatform !== platform
					: null
			);
		};
	});
}

export function observeAsyncAutomation(signal: AbortSignal): Promise<Pick<AutomationEvidence, AsyncKeys>> {
	return Promise.all([
		settle(async () => notificationPermissionQuirk(), signal),
		settle(() => workerUserAgentMismatch(signal), signal)
	]).then(([notification, worker]) => ({
		notificationPermissionQuirk: notification,
		workerUserAgentMismatch: worker
	}));
}

export function collectAutomation(): AutomationEvidence {
	if (
		typeof window === 'undefined' ||
		typeof navigator === 'undefined' ||
		typeof document === 'undefined'
	)
		throw new Error('A browser context is required');
	return {
		version: 3,
		webdriver: observe(() => navigator.webdriver),
		headlessUserAgent: observe(() => {
			const userAgent = navigator.userAgent;
			return typeof userAgent === 'string' && userAgent.length > 0
				? /\bHeadlessChrome\//.test(userAgent)
				: null;
		}),
		seleniumArtifacts: observe(() =>
			['__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_fn', '__selenium_unwrapped']
				.some((name) => name in document)
		),
		phantomArtifacts: observe(() => 'callPhantom' in window || '_phantom' in window),
		platformMismatch: observe(platformMismatch),
		missingChromeObject: observe(() => {
			const ua = text(navigator.userAgent);
			return ua ? chromium(ua) && !(window as { chrome?: unknown }).chrome : null;
		}),
		notificationPermissionQuirk: null,
		emptyPlugins: observe(() => {
			const ua = text(navigator.userAgent);
			return ua ? chromium(ua) && desktop(ua) && navigator.plugins.length === 0 : null;
		}),
		emptyLanguages: observe(() =>
			Array.isArray(navigator.languages) ? navigator.languages.length === 0 : null
		),
		softwareRenderer: null,
		zeroDimensions: observe(() => {
			const sizes = [screen.width, screen.height, outerWidth, outerHeight];
			return sizes.every(Number.isFinite) ? sizes.includes(0) : null;
		}),
		cdpDetected: observe(cdpDetected),
		nativeFunctionTampering: observe(nativeFunctionTampering),
		workerUserAgentMismatch: null
	};
}
