# Sources to review

The harness column names the `scripts/harness.mjs` driver that tests the tool.

## Detectors

| Repo | License | What to look at |
| --- | --- | --- |
| [abrahamjuliot/creepjs](https://github.com/abrahamjuliot/creepjs) | MIT | `src/lies` (proxy and `toString` lie tests), `src/headless`, `src/worker` (worker-scope comparisons), `src/utils/helpers.ts` (engine detection). |
| [fingerprintjs/BotD](https://github.com/fingerprintjs/BotD) | MIT | `src/sources` and `src/detectors`: one file per signal; `distinctive_properties.ts` lists tool globals. |
| [rebrowser/rebrowser-bot-detector](https://github.com/rebrowser/rebrowser-bot-detector) | none stated | CDP leak tests (`Runtime.enable`, main-world execution, `sourceURL`). Read for ideas only. |

## Evasion tools

| Repo | License | Harness | What to look at |
| --- | --- | --- | --- |
| [daijro/camoufox](https://github.com/daijro/camoufox) | MPL-2.0 | `camoufox` | Firefox patches under `browser/patches/`: which properties it spoofs in C++ and whether worker, iframe and main-thread values stay consistent. |
| [Kaliiiiiiiiii-Vinyzu/patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) | Apache-2.0 | `patchright` | Driver patches: isolated worlds, removed `Runtime.enable`, launch flags. |
| [rebrowser/rebrowser-patches](https://github.com/rebrowser/rebrowser-patches) | MIT | `rebrowser-playwright` | Patches to Puppeteer and Playwright for the CDP leaks. |
| [berstend/puppeteer-extra](https://github.com/berstend/puppeteer-extra) | MIT | `playwright-extra-stealth` | `packages/puppeteer-extra-plugin-stealth/evasions`: each evasion is a JS patch that may show. |
| [ultrafunkamsterdam/nodriver](https://github.com/ultrafunkamsterdam/nodriver) | AGPL-3.0 | `nodriver` | Launch flags and CDP usage. |
| [cdpdriver/zendriver](https://github.com/cdpdriver/zendriver) | AGPL-3.0 | none | Maintained nodriver fork; same approach. |
| [seleniumbase/SeleniumBase](https://github.com/seleniumbase/SeleniumBase) | MIT | `seleniumbase-uc` | UC and CDP mode: ChromeDriver renaming and disconnect tricks. |
| [ultrafunkamsterdam/undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) | GPL-3.0 | none | `cdc_` renaming; SeleniumBase UC covers it in the harness. |
| [apify/fingerprint-suite](https://github.com/apify/fingerprint-suite) | Apache-2.0 | none | `fingerprint-injector`: JS overrides of navigator, screen and WebGL values. |
| [CloakHQ/CloakBrowser](https://github.com/CloakHQ/CloakBrowser) | MIT wrapper, closed binary | none | Patched Chromium; the wrapper shows which flags and fingerprints it sets. |

The harness also runs plain `playwright-chromium`, `playwright-firefox` and
`selenium-chromedriver` as positive controls: they must keep showing `webdriver`
and, for ChromeDriver, `driverArtifacts`.
