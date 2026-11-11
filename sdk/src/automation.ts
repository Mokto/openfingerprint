export interface AutomationEvidence {
	version: 6;
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
	driverArtifacts: boolean | null;
	engineMismatch: boolean | null;
	userAgentDataMismatch: boolean | null;
	proportionalMonospace: boolean | null;
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

// Every platform maps the generic monospace family to a fixed-width font. Camoufox, when it claims
// another OS than its host, hides the host's fixed-width fonts and falls back to a proportional one.
// Canvas text ignores page and extension CSS, unlike DOM text.
function proportionalMonospace(): boolean | null {
	const context = document.createElement('canvas').getContext('2d');
	if (!context) return null;
	context.font = '20px monospace';
	const wide = context.measureText('mmmmmmmmmm').width;
	const narrow = context.measureText('iiiiiiiiii').width;
	return wide > 0 && narrow > 0 ? wide > narrow * 1.5 : null;
}

function brands(): { brand: string; version: string }[] | null {
	const list = (navigator as { userAgentData?: { brands?: unknown } }).userAgentData?.brands;
	return Array.isArray(list) ? list : null;
}

function userAgentDataMismatch(): boolean | null {
	const ua = text(navigator.userAgent);
	if (!ua) return null;
	const major = /\bChrome\/(\d+)/.exec(ua)?.[1];
	const chromium = brands()?.find((entry) => entry.brand === 'Chromium')?.version;
	return !!major && !!chromium && chromium.split('.')[0] !== major;
}

const DRIVER_WINDOW = [
	'domAutomation',
	'domAutomationController',
	'__nightmare',
	'_Selenium_IDE_Recorder',
	'_selenium',
	'calledSelenium',
	'__webdriverFunc',
	'__lastWatirAlert',
	'__lastWatirConfirm',
	'__lastWatirPrompt',
	'_WEBDRIVER_ELEM_CACHE',
	'__playwright__binding__',
	'__phantomas',
	'wdioElectron'
];
const DRIVER_DOCUMENT = [
	'__driver_evaluate',
	'__driver_unwrapped',
	'__webdriver_unwrapped',
	'__fxdriver_evaluate',
	'__fxdriver_unwrapped',
	'__webdriver_script_func',
	'__webdriver_script_function',
	'$chrome_asyncScriptInfo',
	'__$webdriverAsyncExecutor'
];

function driverArtifacts(): boolean {
	return (
		DRIVER_WINDOW.some((name) => name in window) ||
		DRIVER_DOCUMENT.some((name) => name in document) ||
		// ChromeDriver's cache globals, e.g. cdc_adoQpoasnfa76pfcZLmcfl_Array; undetected-chromedriver renames the prefix.
		Object.getOwnPropertyNames(window).some((name) => /^[a-z]{3}_\w+_(Array|Promise|Symbol)$/.test(name)) ||
		Object.getOwnPropertyNames(document).some((name) => /^\$cdc_/.test(name)) ||
		['selenium', 'webdriver', 'driver'].some((name) => document.documentElement?.hasAttribute(name))
	);
}

function engine(): string | null {
	try {
		(-1).toFixed(-1);
	} catch (error) {
		const message = error instanceof RangeError ? error.message : '';
		if (/^toFixed\(\) digits argument/.test(message)) return 'v8';
		if (/^precision -1 out of range/.test(message)) return 'spidermonkey';
		if (/^toFixed\(\) argument must be/.test(message)) return 'jsc';
	}
	return null;
}

// iOS user agents are skipped: every iOS browser was WebKit, but EU builds may ship their own engine.
function engineMismatch(): boolean | null {
	const ua = text(navigator.userAgent);
	const actual = engine();
	if (!ua || !actual || /iphone|ipad|ipod/i.test(ua)) return null;
	const claimed = /\b(Chrome|Chromium)\/\d/.test(ua)
		? 'v8'
		: /\bFirefox\/\d/.test(ua)
			? 'spidermonkey'
			: /\bVersion\/[\d.]+.*\bSafari\//.test(ua)
				? 'jsc'
				: null;
	return !!claimed && claimed !== actual;
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

type Frame = Window & typeof globalThis;

// V8 formats a logged error's stack, running Error.prepareStackTrace, only while a CDP client has
// Runtime.enable on: Puppeteer, Playwright, Selenium's ChromeDriver or open DevTools. Since
// Chrome 137 it no longer runs a getter on error.stack, the older form of this check. The
// frame's own Error and console keep page console wrappers that read .stack from tripping it.
function cdpDetected(frame: Frame): boolean {
	let formatted = false;
	const probe = new frame.Error();
	(frame.Error as { prepareStackTrace?: (error: unknown) => string }).prepareStackTrace = (error) => {
		if (error === probe) formatted = true;
		return '';
	};
	frame.console.debug(probe);
	return formatted;
}

// Error monitors such as Sentry replace Function.prototype.toString with a wrapper that still
// answers correctly, so its own source is not evidence of anything. The natives that automation
// tooling patches are read with the toString of the fresh frame instead, which page scripts have
// not touched.
function nativeFunctionPatched(frame: Frame): boolean | null {
	const untouched = frame.Function.prototype.toString;
	if (typeof untouched !== 'function') return null;
	const native = (fn: unknown) =>
		typeof fn === 'function' &&
		!('prototype' in fn) &&
		/\{\s*\[native code\]\s*\}\s*$/.test(untouched.call(fn));
	return ![
		Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')?.get,
		typeof Permissions === 'undefined' ? undefined : Permissions.prototype.query
	].every((fn) => fn === undefined || native(fn));
}

// Without a fresh same-origin frame both answers are unknown, never a guess.
function observeInFrame(): [boolean | null, boolean | null] {
	try {
		const parent = document.body ?? document.documentElement;
		if (!parent) return [null, null];
		const frame = document.createElement('iframe');
		frame.style.display = 'none';
		frame.setAttribute('aria-hidden', 'true');
		frame.tabIndex = -1;
		parent.appendChild(frame);
		try {
			const context = frame.contentWindow as Frame | null;
			if (!context) return [null, null];
			return [observe(() => cdpDetected(context)), observe(() => nativeFunctionPatched(context))];
		} finally {
			frame.remove();
		}
	} catch {
		return [null, null];
	}
}

// A native function refuses a prototype chain through itself with a TypeError. A Proxy around
// it, which toString reports as native code, lets the cycle through. The prototype is restored.
function proxied(fn: unknown): boolean {
	if (typeof fn !== 'function') return false;
	const prototype = Object.getPrototypeOf(fn);
	try {
		Object.setPrototypeOf(fn, Object.create(fn));
		return true;
	} catch (error) {
		return !(error instanceof TypeError);
	} finally {
		Object.setPrototypeOf(fn, prototype);
	}
}

function nativeFunctionTampering(patched: boolean | null): boolean | null {
	try {
		Function.prototype.toString.call({});
		return true;
	} catch (error) {
		if (!(error instanceof TypeError)) return true;
	}
	const webdriver = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')?.get;
	if (
		Object.getOwnPropertyDescriptor(navigator, 'webdriver') ||
		(!webdriver && CSS.supports('border-end-end-radius: initial')) ||
		proxied(webdriver) ||
		proxied(typeof Permissions === 'undefined' ? undefined : Permissions.prototype.query)
	)
		return true;
	const detached = document.createElement('iframe');
	detached.srcdoc = '<!doctype html>';
	// puppeteer-extra-plugin-stealth hands a detached srcdoc frame a window; browsers return null.
	return detached.contentWindow ? true : patched;
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
	const [cdp, patched] = observeInFrame();
	return {
		version: 6,
		webdriver: observe(() => navigator.webdriver),
		headlessUserAgent: observe(() => {
			const userAgent = navigator.userAgent;
			return typeof userAgent === 'string' && userAgent.length > 0
				? /\bHeadlessChrome\//.test(userAgent) ||
						!!brands()?.some((entry) => entry.brand === 'HeadlessChrome')
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
			if (!sizes.every(Number.isFinite)) return null;
			if (!screen.width || !screen.height) return true;
			// A tab opened in the background reports a 0x0 outer window until it is shown.
			return sizes.includes(0) && document.visibilityState === 'hidden' ? null : sizes.includes(0);
		}),
		cdpDetected: cdp,
		nativeFunctionTampering: observe(() => nativeFunctionTampering(patched)),
		workerUserAgentMismatch: null,
		driverArtifacts: observe(driverArtifacts),
		engineMismatch: observe(engineMismatch),
		userAgentDataMismatch: observe(userAgentDataMismatch),
		proportionalMonospace: observe(proportionalMonospace)
	};
}
