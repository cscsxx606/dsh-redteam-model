import { isAbsolute } from 'node:path'

/**
 * Test-only module resolver, injected with `--experimental-loader`.
 *
 * The plugin's own dev dependencies (@deepseek-ai/dsh-settings, ...) are
 * installed by `npm install` in the repo root; when that install has not run
 * (or a sandbox stripped it) tests still need the host packages. This hook
 * maps an unresolvable bare `@deepseek-ai/*` import to the running DSH
 * installation, which is exactly the copy the host hands to plugins.
 *
 * Usage:
 *   DSH_HOST_MODULES=/path/to/@deepseek-ai node --experimental-loader=./tests/helpers/host-resolver.mjs --test tests/*.test.mjs
 */
const hostRoot = process.env.DSH_HOST_MODULES

export async function resolve(specifier, context, next) {
  try {
    return await next(specifier, context)
  } catch (error) {
    if (hostRoot === undefined || !specifier.startsWith('@deepseek-ai/')) throw error
    const candidate = `${hostRoot.replace(/\/$/, '')}/${specifier.slice('@deepseek-ai/'.length)}/lib/index.js`
    if (!isAbsolute(candidate)) throw error
    return next(`file://${candidate}`, context)
  }
}
