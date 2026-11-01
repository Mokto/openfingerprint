export function identityExclusions(
	userAgent: string,
	vendor: string
): ('audio' | 'canvas' | 'screen')[] {
	const version = /\bVersion\/(\d+)(?:\.\d+)*.*\bSafari\//.exec(userAgent);
	// ponytail: reported Safari version gates this policy, not device identity; add release-tested feature gates before covering UA-less WebViews.
	const safari17 =
		vendor.startsWith('Apple') &&
		Number(version?.[1]) >= 17 &&
		!/(?:Chrome|Chromium|CriOS|FxiOS|EdgA?|EdgiOS|OPR)\//.test(userAgent) &&
		!/\bAndroid\b/.test(userAgent);
	return safari17 ? ['audio', 'canvas', 'screen'] : [];
}
