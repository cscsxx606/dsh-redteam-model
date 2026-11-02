/**
 * dsh-redteam-model management host plugin.
 *
 * The plugin itself never installs modes or sub-plugins at startup; all
 * mutations are triggered by the settings page through the loopback RPC.
 */

import path from 'node:path'

import {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  conversationViewWriteApplied,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
  registerConversationViewSettings,
} from './conversationViewSettings.ts'
import { activeProfile, deployGlobalAgents, deployModes, dshHome, ensureProfilePeers, getStatus, healPresetPlanePlugins, installOne, profileWebDir, reconcileProfileBundles, repairMode, scanModes, scanPlugins, scanSkippedPluginEntries, uninstallModes, uninstallOne } from './manager.ts'
import { detectEngineFlavor, isPackagedDesktopHost, normalizePresetComposition } from './manager.ts'
import { ENGINE_PACKAGES, NORMALIZER_VERSION, rewriteCompositionText } from './normalize.ts'
import { OperationQueue } from './operations.ts'
import { registerModelRpc } from './rpc.ts'
import type { HostConnectionHandle } from './types.ts'

export { OperationQueue }
export { activeProfile, deployGlobalAgents, deployModes, dshHome, ensureProfilePeers, getStatus, healPresetPlanePlugins, installOne, profileWebDir, reconcileProfileBundles, repairMode, requiredProfilePeers, scanModes, scanPlugins, scanSkippedPluginEntries, uninstallModes, uninstallOne } from './manager.ts'
export { detectEngineFlavor, isPackagedDesktopHost, normalizePresetComposition }
export { ENGINE_PACKAGES, NORMALIZER_VERSION, rewriteCompositionText }
export { registerModelRpc }
export {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  conversationViewWriteApplied,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
  registerConversationViewSettings,
}

export const name = 'dsh-redteam-model'
export const inject = ['connection']

/** Minimal structural face of the Cordis context this plugin needs. */
export interface HostContext {
  inject(services: readonly string[], callback: (services: Record<string, unknown>) => void): unknown
  effect(cleanup: () => void | (() => void), label?: string): unknown
}

export function apply(ctx: HostContext): void {
  registerConversationViewSettings(ctx)

  // The plugin still never deploys modes or sub-plugins at startup, but the
  // profile rows of ALREADY installed plugins are its own bookkeeping: first
  // restore preset-plane dependencies a pre-fix profile detector stranded in
  // the wrong profile (their absence leaves preset rows that never start),
  // then heal a bundle manifest that an older release (or a bundle reconcile
  // reading a stale `dsh.bundle` declaration) left naming a preset-plane
  // plugin, which would otherwise report "broken — repair" on this boot and
  // every boot after it. Never fatal: an unreadable profile must not keep the
  // host from booting.
  try {
    healPresetPlanePlugins()
  } catch {
    /* getStatus reports the profile state to the settings page instead. */
  }
  try {
    reconcileProfileBundles()
  } catch {
    /* getStatus reports the profile state to the settings page instead. */
  }
  try {
    // Linked plugins import host-supplied packages (@deepseek-ai/dsh-tools,
    // schemastery, ...). The host only routes those imports when the profile
    // manifest declares them as peers; without the rows they load as plain
    // Node resolutions from a `link:`ed tree and fail. Safe to run on every
    // boot: it writes nothing once the rows exist.
    ensureProfilePeers()
  } catch {
    /* getStatus reports the profile state to the settings page instead. */
  }

  const queue = new OperationQueue(path.join(profileWebDir(), '.dsh-redteam-model-operations.json'))

  ctx.inject(['connection'], (web: Record<string, unknown>) => {
    const { connection } = web as { connection: HostConnectionHandle }
    registerModelRpc(connection, queue)
  })

  ctx.effect(() => () => {
    queue.dispose()
  }, 'dsh-redteam-model: queue')
}
