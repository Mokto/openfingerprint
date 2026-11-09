// Obfuscation, not encryption: the key is public. It hides evidence from casual
// inspection and makes identical devices produce different strings.
const SEED = 0x6f667031;

export function seal(value: unknown): string {
	const json = new TextEncoder().encode(JSON.stringify(value));
	const out = new Uint8Array(4 + json.length);
	crypto.getRandomValues(out.subarray(0, 4));
	let state = (new DataView(out.buffer).getUint32(0) ^ SEED) >>> 0;
	for (let i = 0; i < json.length; i++) {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = Math.imul(state ^ (state >>> 15), state | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		out[4 + i] = json[i]! ^ ((t ^ (t >>> 14)) & 255);
	}
	let text = '';
	for (let i = 0; i < out.length; i += 0x8000)
		text += String.fromCharCode(...out.subarray(i, i + 0x8000));
	return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
