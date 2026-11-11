# Sources to review

The harness column names the `scripts/harness.mjs` driver that tests the tool.

## Detectors

| Repo | License | What to look at |
| --- | --- | --- |
| [abrahamjuliot/creepjs](https://github.com/abrahamjuliot/creepjs) | MIT | `src/lies` (proxy and `toString` lie tests), `src/headless`, `src/worker` (worker-scope comparisons), `src/utils/helpers.ts` (engine detection). |
| [fingerprintjs/BotD](https://github.com/fingerprintjs/BotD) | MIT | `src/sources` and `src/detectors`: one file per signal; `distinctive_properties.ts` lists tool globals. |
| [rebrowser/rebrowser-bot-detector](https://github.com/rebrowser/rebrowser-bot-detector) | none stated | CDP leak tests (`Runtime.enable`, main-world execution, `sourceURL`). Read for ideas only. |

## Anti-detect browsers

Camoufox's competitors: browser builds that spoof the fingerprint in the engine, not in page
script. Test every one the harness can launch.

| Repo | License | Harness | What to look at |
| --- | --- | --- | --- |
| [daijro/camoufox](https://github.com/daijro/camoufox) | MPL-2.0 | `camoufox`, `camoufox-windows`, `camoufox-macos` | Firefox patches under `browser/patches/`: which properties it spoofs in C++ and whether worker, iframe and main-thread values stay consistent. |
| [clearcotelabs/clearcote-browser](https://github.com/clearcotelabs/clearcote-browser) | BSD-3-Clause | `clearcote` | ungoogled-chromium fork with published patches and a seeded fingerprint. |
| [CloakHQ/CloakBrowser](https://github.com/CloakHQ/CloakBrowser) | MIT wrapper, closed binary | `cloakbrowser` | Patched Chromium; the wrapper shows which flags and fingerprints it sets. Needs a free licence key: run `npx cloakbrowser login` in `~/.cache/openfingerprint-stealth`. |
| [h4ckf0r0day/obscura](https://github.com/h4ckf0r0day/obscura) | Apache-2.0 | `obscura` | Engine written in Rust on V8 that claims to be Chrome; look for Web APIs it lacks or implements differently. |
| [feder-cr/invisible_playwright](https://github.com/feder-cr/invisible_playwright) | MIT | `invisible-playwright` | Patched Firefox like Camoufox. Publishes Linux and Windows binaries only, so the driver fails on macOS. |
| [botswin/BotBrowser](https://github.com/botswin/BotBrowser) | MIT wrapper, closed binary | none | Chromium build driven by encrypted profiles; profiles for current releases need a subscription. Read its docs for what it spoofs. |
| [donutbrowser/donutbrowser](https://github.com/donutbrowser/donutbrowser) | AGPL-3.0 | none | Desktop profile manager on its Chromium fork (Wayfern); no headless launcher. |

Commercial anti-detect browsers (GoLogin, Multilogin, Kameleo, AdsPower, Dolphin Anty, Octo
Browser) need paid accounts and have no harness driver; read their public docs and changelogs
for what they claim to spoof.

## Evasion tools

| Repo | License | Harness | What to look at |
| --- | --- | --- | --- |
| [Kaliiiiiiiiii-Vinyzu/patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) | Apache-2.0 | `patchright` | Driver patches: isolated worlds, removed `Runtime.enable`, launch flags. |
| [rebrowser/rebrowser-patches](https://github.com/rebrowser/rebrowser-patches) | MIT | `rebrowser-playwright` | Patches to Puppeteer and Playwright for the CDP leaks. |
| [berstend/puppeteer-extra](https://github.com/berstend/puppeteer-extra) | MIT | `playwright-extra-stealth` | `packages/puppeteer-extra-plugin-stealth/evasions`: each evasion is a JS patch that may show. |
| [ultrafunkamsterdam/nodriver](https://github.com/ultrafunkamsterdam/nodriver) | AGPL-3.0 | `nodriver` | Launch flags and CDP usage. |
| [cdpdriver/zendriver](https://github.com/cdpdriver/zendriver) | AGPL-3.0 | `zendriver` | Maintained nodriver fork; same approach. |
| [autoscrape-labs/pydoll](https://github.com/autoscrape-labs/pydoll) | MIT | `pydoll` | CDP driver without WebDriver; what it changes at launch and per page. |
| [omkarcloud/botasaurus](https://github.com/omkarcloud/botasaurus) | MIT | none | CDP driver with human-like input; uses the installed Chrome. |
| [seleniumbase/SeleniumBase](https://github.com/seleniumbase/SeleniumBase) | MIT | `seleniumbase-uc` | UC and CDP mode: ChromeDriver renaming and disconnect tricks. |
| [ultrafunkamsterdam/undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) | GPL-3.0 | none | `cdc_` renaming; SeleniumBase UC covers it in the harness. |
| [apify/fingerprint-suite](https://github.com/apify/fingerprint-suite) | Apache-2.0 | none | `fingerprint-injector`: JS overrides of navigator, screen and WebGL values. |

The harness also runs plain `playwright-chromium`, `playwright-firefox` and
`selenium-chromedriver` as positive controls: they must keep showing `webdriver`
and, for ChromeDriver, `driverArtifacts`.
