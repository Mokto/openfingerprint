export interface AutomationEvidence {
	version: 1;
	webdriver: boolean | null;
	headlessUserAgent: boolean | null;
	seleniumArtifacts: boolean | null;
	phantomArtifacts: boolean | null;
}

function observe(read: () => unknown): boolean | null {
	try {
		const value = read();
		return typeof value === 'boolean' ? value : null;
	} catch {
		return null;
	}
}

export function collectAutomation(): AutomationEvidence {
	if (
		typeof window === 'undefined' ||
		typeof navigator === 'undefined' ||
		typeof document === 'undefined'
	)
		throw new Error('A browser context is required');
	return {
		version: 1,
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
		phantomArtifacts: observe(() => 'callPhantom' in window || '_phantom' in window)
	};
}
