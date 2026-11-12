import { engine } from './automation';

export interface BehaviorEvidence {
	version: 2;
	watchedMs: number;
	pointerMoves: number;
	mouseClicks: number;
	clicksWithoutMovement: number;
	centeredClicks: number;
	keys: number;
	instantKeys: number;
	insertedTexts: number;
	touches: number;
	wheels: number;
	untrustedEvents: number;
}

type Counts = Omit<BehaviorEvidence, 'version' | 'watchedMs'>;

interface CallSite {
	getFileName(): string | null | undefined;
	getScriptNameOrSourceURL(): string | null | undefined;
	getLineNumber(): number | null;
	getFunctionName(): string | null;
	isEval(): boolean;
	getScriptHash?(): string;
}

let started: number | null = null;
let protocolScript: boolean | null = null;
const counts: Counts = {
	pointerMoves: 0,
	mouseClicks: 0,
	clicksWithoutMovement: 0,
	centeredClicks: 0,
	keys: 0,
	instantKeys: 0,
	insertedTexts: 0,
	touches: 0,
	wheels: 0,
	untrustedEvents: 0
};
const restore: (() => void)[] = [];

// V8 gives code that a DevTools protocol client compiled with Runtime.evaluate neither a file
// name nor a script hash. Page scripts without a URL (dynamically inserted inline scripts,
// setTimeout strings, javascript: links) have a hash; cross-origin scripts without CORS have no
// hash but keep their URL, and their eval frames are marked as eval. Puppeteer names its code
// with a sourceURL comment. ChromeDriver compiles its call_function.js helper with
// Runtime.callFunctionOn, which gets a hash; its callFunction sits hundreds of lines into it.
function v8ProtocolFrame(site: CallSite): boolean {
	if (/^(pptr:|__puppeteer_evaluation_script__)/.test(String(site.getScriptNameOrSourceURL())))
		return true;
	const file = site.getFileName();
	if (file === '' && site.getFunctionName() === 'callFunction' && (site.getLineNumber() ?? 0) > 100)
		return true;
	return (
		file === '' &&
		site.getLineNumber() !== null &&
		!site.isEval() &&
		typeof site.getScriptHash === 'function' &&
		site.getScriptHash() === ''
	);
}

function v8Caller(): boolean {
	const constructor = Error as ErrorConstructor & {
		prepareStackTrace?: unknown;
		stackTraceLimit?: number;
	};
	const { prepareStackTrace, stackTraceLimit } = constructor;
	const own = Object.prototype.hasOwnProperty.call(constructor, 'prepareStackTrace');
	let found = false;
	try {
		constructor.stackTraceLimit = 50;
		constructor.prepareStackTrace = (_: Error, sites: CallSite[]) => {
			found = sites.some(v8ProtocolFrame);
			return '';
		};
		void new Error().stack;
	} finally {
		if (own) constructor.prepareStackTrace = prepareStackTrace;
		else delete constructor.prepareStackTrace;
		constructor.stackTraceLimit = stackTraceLimit;
	}
	return found;
}

// Firefox names code run through its Debugger API, which Juggler (Playwright, Camoufox),
// WebDriver BiDi and the DevTools console use, "debugger eval code".
function geckoCaller(): boolean {
	return /@debugger eval code[: ]/.test(String(new Error().stack));
}

// Methods that scraping and driver code calls in the page's own JavaScript world. Hot layout
// reads such as getBoundingClientRect stay untouched: each trapped call costs a stack capture
// (about 2.5 µs) until the first hit removes every trap.
function targets(): [object, string, 'value' | 'get'][] {
	const scope = window as unknown as Record<string, { prototype?: object } | undefined>;
	const list: [string, string, 'value' | 'get'][] = [
		['Document', 'querySelector', 'value'],
		['Document', 'querySelectorAll', 'value'],
		['Document', 'getElementById', 'value'],
		['Document', 'getElementsByClassName', 'value'],
		['Document', 'getElementsByTagName', 'value'],
		['Document', 'evaluate', 'value'],
		['Document', 'title', 'get'],
		['Element', 'querySelector', 'value'],
		['Element', 'querySelectorAll', 'value'],
		['Element', 'getElementsByClassName', 'value'],
		['Element', 'getElementsByTagName', 'value'],
		['Element', 'outerHTML', 'get'],
		['HTMLElement', 'innerText', 'get'],
		['HTMLElement', 'click', 'value']
	];
	return list.flatMap(([name, key, kind]) => {
		const prototype = scope[name]?.prototype;
		return prototype ? [[prototype, key, kind] as [object, string, 'value' | 'get']] : [];
	});
}

function trap(caller: () => boolean) {
	const hit = () => {
		protocolScript = true;
		while (restore.length) restore.pop()?.();
	};
	for (const [owner, key, kind] of targets()) {
		const descriptor = Object.getOwnPropertyDescriptor(owner, key);
		const original = descriptor?.[kind];
		if (!descriptor?.configurable || typeof original !== 'function') continue;
		const wrapped = new Proxy(original, {
			apply(target, self, args) {
				try {
					if (protocolScript === false && caller()) hit();
				} catch {}
				return Reflect.apply(target, self, args);
			}
		});
		Object.defineProperty(owner, key, { ...descriptor, [kind]: wrapped });
		restore.push(() => Object.defineProperty(owner, key, descriptor));
	}
}

function listen() {
	let moves = 0;
	let movesAtDown = 0;
	let pointerType = '';
	let keySinceInput = false;
	const pressed = new Map<string, number>();
	const on = (type: string, handler: (event: Event) => void) =>
		addEventListener(type, handler, { capture: true, passive: true });
	const untrusted = (event: Event) => {
		if (event.isTrusted) return false;
		counts.untrustedEvents++;
		return true;
	};
	on('pointermove', (event) => {
		if (event.isTrusted && (event as PointerEvent).pointerType === 'mouse') {
			counts.pointerMoves++;
			moves++;
		}
	});
	on('pointerdown', (event) => {
		if (untrusted(event)) return;
		pointerType = (event as PointerEvent).pointerType;
		movesAtDown = moves;
		moves = 0;
	});
	on('click', (event) => {
		const click = event as MouseEvent & { pointerType?: string };
		// A click from the keyboard has detail 0 and no pointer position.
		// WebKit labels a touch compatibility click as mouse; the preceding press stays touch.
		if (
			untrusted(event) || click.detail === 0 || pointerType !== 'mouse' ||
			(click.pointerType && click.pointerType !== 'mouse')
		) return;
		counts.mouseClicks++;
		if (movesAtDown <= 1) counts.clicksWithoutMovement++;
		const target = event.target;
		if (!(target instanceof Element)) return;
		const box = target.getBoundingClientRect();
		if (
			box.width > 4 &&
			box.height > 4 &&
			Math.abs(click.clientX - (box.left + box.width / 2)) <= 1 &&
			Math.abs(click.clientY - (box.top + box.height / 2)) <= 1
		)
			counts.centeredClicks++;
	});
	on('keydown', (event) => {
		const key = event as KeyboardEvent;
		if (untrusted(event) || key.repeat || key.isComposing || key.keyCode === 229) return;
		counts.keys++;
		keySinceInput = true;
		pressed.set(key.code, event.timeStamp);
	});
	on('keyup', (event) => {
		const key = event as KeyboardEvent;
		const down = pressed.get(key.code);
		pressed.delete(key.code);
		if (event.isTrusted && down !== undefined && event.timeStamp - down < 5) counts.instantKeys++;
	});
	on('input', (event) => {
		if (untrusted(event)) return;
		if ((event as InputEvent).inputType === 'insertText' && !keySinceInput) counts.insertedTexts++;
		keySinceInput = false;
	});
	on('touchstart', (event) => {
		if (!untrusted(event)) counts.touches++;
	});
	on('wheel', (event) => {
		if (!untrusted(event)) counts.wheels++;
	});
	on('mousedown', untrusted);
	on('keyup', untrusted);
}

/**
 * Starts watching the page until it unloads: traps for driver code calling DOM methods, and
 * counts of pointer, keyboard and touch input. Call it as early as possible; `collect()` then
 * reports what was seen so far. Calling it again does nothing.
 */
export function watch(): void {
	if (started !== null || typeof window === 'undefined' || typeof document === 'undefined') return;
	started = performance.now();
	listen();
	const kind = engine();
	if (kind !== 'v8' && kind !== 'spidermonkey') return;
	protocolScript = false;
	trap(kind === 'v8' ? v8Caller : geckoCaller);
}

/** True once code run through a debugging protocol called a trapped DOM method; null when not watching or the engine can't tell. */
export function observedProtocolScript(): boolean | null {
	return protocolScript;
}

export function collectBehavior(): BehaviorEvidence | null {
	if (started === null) return null;
	return { version: 2, watchedMs: Math.round(performance.now() - started), ...counts };
}
