type NavigatorDetails = Navigator & {
	deviceMemory?: number;
	oscpu?: string;
	cpuClass?: string;
	userAgentData?: {
		brands: { brand: string; version: string }[];
		mobile: boolean;
		platform: string;
	};
};

function available(name: 'localStorage' | 'sessionStorage' | 'indexedDB'): boolean | 'blocked' {
	try {
		return !!globalThis[name];
	} catch {
		return 'blocked';
	}
}

export const environment = {
	platform: () => JSON.stringify([navigator.platform, navigator.maxTouchPoints]),
	hardware: () =>
		JSON.stringify([
			navigator.hardwareConcurrency,
			(navigator as NavigatorDetails).deviceMemory ?? null,
			(navigator as NavigatorDetails).oscpu ?? null,
			(navigator as NavigatorDetails).cpuClass ?? null
		]),
	locale: () => {
		const options = Intl.DateTimeFormat().resolvedOptions();
		// Not navigator.languages (incognito/Safari reduce it to one entry) or the current
		// UTC offset (changes at DST; the zone name already covers it).
		return JSON.stringify([navigator.language, options.timeZone, options.locale]);
	},
	display: () => JSON.stringify(screen.colorDepth),
	screen: () =>
		JSON.stringify([[screen.width, screen.height].sort((a, b) => a - b), devicePixelRatio]),
	browser: () => {
		const data = (navigator as NavigatorDetails).userAgentData;
		return JSON.stringify([
			navigator.userAgent,
			navigator.vendor,
			data ? [data.brands.map((b) => [b.brand, b.version]), data.mobile, data.platform] : null,
			Array.from(navigator.plugins || [], (plugin) => [
				plugin.name,
				plugin.filename,
				plugin.description,
				Array.from(plugin, (mime) => [mime.type, mime.suffixes])
			])
		]);
	},
	features: () =>
		JSON.stringify([
			available('localStorage'),
			available('sessionStorage'),
			available('indexedDB'),
			'openDatabase' in globalThis,
			navigator.cookieEnabled,
			navigator.pdfViewerEnabled,
			'ApplePaySession' in globalThis,
			'privateClickMeasurement' in document.createElement('a'),
			'ontouchstart' in globalThis,
			typeof TouchEvent === 'function'
		]),
	media: () =>
		JSON.stringify(
			[
				'(color-gamut: srgb)',
				'(color-gamut: p3)',
				'(color-gamut: rec2020)',
				'(dynamic-range: high)',
				'(monochrome)',
				'(forced-colors: active)',
				'(inverted-colors: inverted)',
				'(prefers-contrast: more)',
				'(prefers-contrast: less)',
				'(prefers-reduced-motion: reduce)',
				'(prefers-reduced-transparency: reduce)',
				'(pointer: coarse)',
				'(hover: hover)'
			].map((query) => matchMedia(query).matches)
		),
	math: () =>
		JSON.stringify([
			Math.acos(0.31),
			Math.acosh(1.7),
			Math.asin(0.61),
			Math.asinh(0.37),
			Math.atan(1.7),
			Math.atanh(0.23),
			Math.cos(1e19),
			Math.sin(1e19),
			Math.tan(1e19),
			Math.cosh(0.71),
			Math.sinh(0.61),
			Math.tanh(0.39),
			Math.exp(0.17),
			Math.expm1(0.29),
			Math.log(1.7),
			Math.log1p(0.23),
			Math.log10(1.3),
			Math.cbrt(1.7),
			Math.pow(1.7, 0.31)
		]),
	architecture: () =>
		JSON.stringify(Array.from(new Uint8Array(new Float32Array([Infinity - Infinity]).buffer)))
};
