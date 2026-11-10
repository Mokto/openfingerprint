export interface SpoofingEvidence {
	version: 1;
	userAgent: string | null;
	language: string | null;
	clientHints: {
		brands: { brand: string; version: string }[];
		mobile: boolean;
		platform: string;
	} | null;
}

// The API compares these with the headers of the request that carries the token, so they
// are sent as read, not hashed. The limits match what the API accepts.
function text(read: () => unknown, limit: number): string | null {
	try {
		const value = read();
		return typeof value === 'string' && value.length > 0 && value.length <= limit ? value : null;
	} catch {
		return null;
	}
}

function clientHints(): SpoofingEvidence['clientHints'] {
	try {
		const data = (navigator as Navigator & { userAgentData?: Record<string, unknown> }).userAgentData;
		if (!data) return null;
		const { brands, mobile, platform } = data;
		if (!Array.isArray(brands) || brands.length > 16 || typeof mobile !== 'boolean') return null;
		if (typeof platform !== 'string' || platform.length > 64) return null;
		const list = brands.map((entry) => ({ brand: entry?.brand, version: entry?.version }));
		const valid = list.every(
			(b): b is { brand: string; version: string } =>
				typeof b.brand === 'string' &&
				b.brand.length <= 64 &&
				typeof b.version === 'string' &&
				b.version.length <= 32
		);
		return valid ? { brands: list, mobile, platform } : null;
	} catch {
		return null;
	}
}

export function collectSpoofing(): SpoofingEvidence {
	return {
		version: 1,
		userAgent: text(() => navigator.userAgent, 1024),
		language: text(() => navigator.language, 64),
		clientHints: clientHints()
	};
}
