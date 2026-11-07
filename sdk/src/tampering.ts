export interface TamperingEvidence {
	version: 1;
	canvasReadbackAltered: boolean | null;
	audioRenderAltered: boolean | null;
}

const empty = (): TamperingEvidence => ({
	version: 1,
	canvasReadbackAltered: null,
	audioRenderAltered: null
});

// Opaque, flat fills have one correct readback in every engine; farbling and
// noise-injecting extensions change low bits, and Firefox resistFingerprinting
// blanks or randomizes the data.
function canvasReadbackAltered(): boolean | null {
	const size = 16;
	const canvas = document.createElement('canvas');
	canvas.width = canvas.height = size;
	const context = canvas.getContext('2d', { willReadFrequently: true });
	if (!context) return null;
	const colors = Array.from({ length: size }, (_, i) => [
		(i * 17) & 255,
		(i * 53 + 7) & 255,
		(i * 89 + 13) & 255
	]);
	colors.forEach((color, x) => {
		context.fillStyle = `rgb(${color})`;
		context.fillRect(x, 0, 1, size);
	});
	const { data } = context.getImageData(0, 0, size, size);
	if (data.length !== size * size * 4) return null;
	return colors.some(([r, g, b], x) =>
		Array.from({ length: size }, (_, y) => (y * size + x) * 4).some(
			(at) => data[at] !== r || data[at + 1] !== g || data[at + 2] !== b || data[at + 3] !== 255
		)
	);
}

async function audioRenderAltered(): Promise<boolean | null> {
	if (typeof OfflineAudioContext === 'undefined') return null;
	const context = new OfflineAudioContext(1, 4410, 44100);
	const source = context.createConstantSource();
	source.offset.value = 0.5;
	source.connect(context.destination);
	source.start();
	const samples = (await context.startRendering()).getChannelData(0);
	if (samples.length !== 4410) return null;
	return samples.some((sample) => sample !== 0.5);
}

function settle(work: () => Promise<boolean | null> | boolean | null, signal: AbortSignal) {
	return new Promise<boolean | null>((resolve) => {
		const done = () => resolve(null);
		signal.addEventListener('abort', done, { once: true });
		if (signal.aborted) return done();
		Promise.resolve()
			.then(work)
			.then((value) => resolve(typeof value === 'boolean' ? value : null), done);
	});
}

export function observeTampering(signal: AbortSignal): Promise<TamperingEvidence> {
	return Promise.all([
		settle(canvasReadbackAltered, signal),
		settle(audioRenderAltered, signal)
	]).then(([canvasReadbackAltered, audioRenderAltered]) => ({
		...empty(),
		canvasReadbackAltered,
		audioRenderAltered
	}));
}

export const unobservedTampering = empty;
