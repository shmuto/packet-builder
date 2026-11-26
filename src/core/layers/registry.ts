import { arpDefinition } from './arp';
import { bgpDefinition } from './bgp';
import {
  createLayerRegistry,
  type BaseLayer,
  type LayerDefinition,
  type LayerRegistry,
  type ProtocolTables,
} from './definition';
import { ethernetDefinition } from './ethernet';
import { greDefinition } from './gre';
import { icmpDefinition } from './icmp';
import { icmpv6Definition } from './icmpv6';
import { ipv4Definition } from './ipv4';
import { ipv6Definition } from './ipv6';
import { tcpDefinition } from './tcp';
import type { Layer } from './types';
import { udpDefinition } from './udp';
import { vlanDefinition } from './vlan';
import { vxlanDefinition } from './vxlan';

/**
 * Returns the ordered tuple of all built-in protocol definitions.
 * Built inside a function so standalone imports of individual protocol modules
 * never read another protocol definition before module evaluation completes.
 */
export function getLayerDefinitions() {
  return [
    ethernetDefinition,
    vlanDefinition,
    arpDefinition,
    ipv4Definition,
    ipv6Definition,
    icmpDefinition,
    icmpv6Definition,
    greDefinition,
    udpDefinition,
    tcpDefinition,
    vxlanDefinition,
    bgpDefinition,
  ] as const;
}

/** Union of all built-in layer type identifiers, derived directly from the registry. */
export type LayerType = ReturnType<typeof getLayerDefinitions>[number]['type'];

let cachedDefaultRegistry: LayerRegistry<Layer> | null = null;

/**
 * Returns the default built-in layer registry (lazily initialized on first access).
 */
export function getDefaultLayerRegistry(): LayerRegistry<Layer> {
  if (cachedDefaultRegistry === null) {
    cachedDefaultRegistry = createLayerRegistry(
      getLayerDefinitions() as unknown as readonly LayerDefinition<Layer>[],
    );
  }
  return cachedDefaultRegistry;
}

/** Returns the default bidirectional next-protocol lookup tables. */
export function getDefaultProtocolTables(): ProtocolTables<BaseLayer> {
  return getDefaultLayerRegistry().tables as unknown as ProtocolTables<BaseLayer>;
}

/** Creates a default instance of any built-in layer via the registry. */
export function createDefaultLayerByType(type: LayerType): Layer {
  const def = getDefaultLayerRegistry().get(type);
  if (!def) {
    throw new Error(`Unknown layer type: ${type}`);
  }
  return def.createDefault();
}

export { createLayerRegistry, type LayerDefinition, type LayerRegistry, type ProtocolTables };
