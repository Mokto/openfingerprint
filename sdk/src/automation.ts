export interface AutomationEvidence {
	version: 2;
	webdriver: boolean | null;
	headlessUserAgent: boolean | null;
	seleniumArtifacts: boolean | null;
	phantomArtifacts: boolean | null;
	softwareRenderer: boolean | null;
	missingChromeObject: boolean | null;
	noLanguages: boolean | null;
	platformInconsistent: boolean | null;
}

const platformPattern: Record<string, RegExp> = {
	Windows: /^Win/,
	macOS: /^Mac/,
	Linux: /^Linux/,
	Android: /^Linux/
};

function observe(read: () => unknown): boolean | null {
	try {
		const value = read();
		return typeof value === 'boolean' ? value : null;
	} catch {
		return null;
	}
}

export function softwareRenderer(renderer: unknown): boolean | null {
	return typeof renderer === 'string' && renderer.length > 0
		? /SwiftShader|llvmpipe|softpipe|Software Rasterizer/i.test(renderer)
		: null;
}

export function collectAutomation(): AutomationEvidence {
	if (
		typeof window === 'undefined' ||
		typeof navigator === 'undefined' ||
		typeof document === 'undefined'
	)
		throw new Error('A browser context is required');
	return {
		version: 2,
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
		// Filled by collect() from the GPU probe; creating another WebGL context here can block the main thread.
		softwareRenderer: null,
		missingChromeObject: observe(() => {
			const ua = navigator.userAgent;
			return /\bChrome\/\d/.test(ua) && !/\b(?:CriOS|FxiOS|EdgiOS)\/|; wv\)/.test(ua)
				? !('chrome' in window)
				: null;
		}),
		noLanguages: observe(() =>
			Array.isArray(navigator.languages) ? navigator.languages.length === 0 : null
		),
		platformInconsistent: observe(() => {
			const claimed = (navigator as Navigator & { userAgentData?: { platform?: string } })
				.userAgentData?.platform;
			const pattern = claimed ? platformPattern[claimed] : undefined;
			return pattern ? !pattern.test(navigator.platform) : null;
		})
	};
}
