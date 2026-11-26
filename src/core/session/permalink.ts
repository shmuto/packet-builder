import { decodeUtf8Strict, encodeUtf8 } from '../bytes';
import { err, ok, type Result } from '../result';
import type { BgpLargeCommunity, BgpOriginValue } from '../bgp';
import type {
  OriginatedRoute,
  RouterCapabilities,
  RouterConfig,
  RouterId,
  SessionConfig,
  SessionEvent,
} from './types';

export const SESSION_PERMALINK_VERSION = 1;
export const SESSION_PERMALINK_PREFIX = `s${SESSION_PERMALINK_VERSION}=`;
export const LEGACY_PERMALINK_PREFIX = 'p1=';
export const MAX_SESSION_ROUTES = 32;
export const MAX_SESSION_EVENTS = 64;

export interface SessionPermalinkState {
  readonly scenarioId: string;
  readonly config: SessionConfig;
  readonly events: readonly SessionEvent[];
}

const FRAGMENT_VERSION_PATTERN = /^s([0-9]+)=(.*)$/s;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function isLegacyPermalinkHash(hash: string): boolean {
  const trimmed = hash.startsWith('#') ? hash.slice(1) : hash;
  return trimmed.startsWith(LEGACY_PERMALINK_PREFIX);
}

export function buildLegacyPermalinkUrl(hash: string): string {
  const trimmed = hash.startsWith('#') ? hash.slice(1) : hash;
  return `./legacy/#${trimmed}`;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    let chunk = '';
    for (let j = 0; j < slice.length; j++) {
      chunk += String.fromCharCode(slice[j]);
    }
    binary += chunk;
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(encoded: string): Result<Uint8Array> {
  if (encoded.length === 0) {
    return err('Permalink data is empty.');
  }
  if (!BASE64URL_PATTERN.test(encoded) || encoded.length % 4 === 1) {
    return err('Invalid base64url encoding in permalink.');
  }
  const padded =
    encoded.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (encoded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return err('Invalid base64url encoding in permalink.');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return ok(bytes);
}

export function buildSessionPermalinkUrl(
  origin: string,
  pathname: string,
  fragment: string,
): string {
  const normalized = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  return `${origin}${pathname}#${normalized}`;
}

export function encodeSessionPermalink(state: SessionPermalinkState): string {
  const canonical: SessionPermalinkState = {
    scenarioId: state.scenarioId,
    config: state.config,
    events: state.events,
  };
  const json = JSON.stringify(canonical);
  return `${SESSION_PERMALINK_PREFIX}${bytesToBase64Url(encodeUtf8(json))}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkNoForbiddenKeysRecursive(value: unknown, depth = 0): Result<void> {
  if (depth > 32) {
    return err('Permalink payload nesting is too deep.');
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const res = checkNoForbiddenKeysRecursive(item, depth + 1);
      if (!res.ok) return res;
    }
    return ok(undefined);
  }
  if (isPlainObject(value)) {
    for (const key of Object.keys(value)) {
      if (FORBIDDEN_KEYS.has(key)) {
        return err(`Permalink contains forbidden key "${key}".`);
      }
      const res = checkNoForbiddenKeysRecursive(value[key], depth + 1);
      if (!res.ok) return res;
    }
  }
  return ok(undefined);
}

function validateAllowedKeys(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  context: string,
): Result<Record<string, unknown>> {
  if (!isPlainObject(value)) {
    return err(`${context} must be an object.`);
  }
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) {
      return err(`${context} contains forbidden key "${key}".`);
    }
    if (!allowed.has(key)) {
      return err(`${context} has unexpected key "${key}".`);
    }
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      return err(`${context} is missing required key "${key}".`);
    }
  }
  return ok(value);
}

function expectString(obj: Record<string, unknown>, key: string, ctx: string): Result<string> {
  const v = obj[key];
  if (typeof v !== 'string') return err(`${ctx}.${key} must be a string.`);
  return ok(v);
}

function expectOptionalString(
  obj: Record<string, unknown>,
  key: string,
  ctx: string,
): Result<string | undefined> {
  if (!Object.prototype.hasOwnProperty.call(obj, key) || obj[key] === undefined) {
    return ok(undefined);
  }
  const v = obj[key];
  if (typeof v !== 'string') return err(`${ctx}.${key} must be a string.`);
  return ok(v);
}

function expectBoolean(obj: Record<string, unknown>, key: string, ctx: string): Result<boolean> {
  const v = obj[key];
  if (typeof v !== 'boolean') return err(`${ctx}.${key} must be a boolean.`);
  return ok(v);
}

function expectUint(
  obj: Record<string, unknown>,
  key: string,
  max: number,
  ctx: string,
): Result<number> {
  const v = obj[key];
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > max) {
    return err(`${ctx}.${key} must be an integer between 0 and ${max}.`);
  }
  return ok(v);
}

function expectOptionalUint(
  obj: Record<string, unknown>,
  key: string,
  max: number,
  ctx: string,
): Result<number | undefined> {
  if (!Object.prototype.hasOwnProperty.call(obj, key) || obj[key] === undefined) {
    return ok(undefined);
  }
  return expectUint(obj, key, max, ctx);
}

function expectRouterId(obj: Record<string, unknown>, key: string, ctx: string): Result<RouterId> {
  const v = obj[key];
  if (v !== 'A' && v !== 'B') {
    return err(`${ctx}.${key} must be "A" or "B".`);
  }
  return ok(v);
}

function validateCapabilities(raw: unknown, ctx: string): Result<RouterCapabilities> {
  const objRes = validateAllowedKeys(
    raw,
    ['mpIpv4Unicast', 'mpIpv6Unicast', 'routeRefresh', 'fourOctetAs', 'gracefulRestart'],
    [],
    ctx,
  );
  if (!objRes.ok) return objRes;
  const obj = objRes.value;
  const mpIpv4Unicast = expectBoolean(obj, 'mpIpv4Unicast', ctx);
  const mpIpv6Unicast = expectBoolean(obj, 'mpIpv6Unicast', ctx);
  const routeRefresh = expectBoolean(obj, 'routeRefresh', ctx);
  const fourOctetAs = expectBoolean(obj, 'fourOctetAs', ctx);
  const gracefulRestart = expectBoolean(obj, 'gracefulRestart', ctx);
  if (!mpIpv4Unicast.ok) return mpIpv4Unicast;
  if (!mpIpv6Unicast.ok) return mpIpv6Unicast;
  if (!routeRefresh.ok) return routeRefresh;
  if (!fourOctetAs.ok) return fourOctetAs;
  if (!gracefulRestart.ok) return gracefulRestart;
  return ok({
    mpIpv4Unicast: mpIpv4Unicast.value,
    mpIpv6Unicast: mpIpv6Unicast.value,
    routeRefresh: routeRefresh.value,
    fourOctetAs: fourOctetAs.value,
    gracefulRestart: gracefulRestart.value,
  });
}

function validateRoute(raw: unknown, ctx: string): Result<OriginatedRoute> {
  const objRes = validateAllowedKeys(
    raw,
    ['id', 'prefix', 'origin'],
    ['med', 'localPref', 'communities', 'largeCommunities'],
    ctx,
  );
  if (!objRes.ok) return objRes;
  const obj = objRes.value;

  const id = expectString(obj, 'id', ctx);
  const prefix = expectString(obj, 'prefix', ctx);
  const origin = expectUint(obj, 'origin', 2, ctx);
  const med = expectOptionalUint(obj, 'med', 0xffffffff, ctx);
  const localPref = expectOptionalUint(obj, 'localPref', 0xffffffff, ctx);
  if (!id.ok) return id;
  if (!prefix.ok) return prefix;
  if (!origin.ok) return origin;
  if (!med.ok) return med;
  if (!localPref.ok) return localPref;

  let communities: number[] | undefined;
  if (Object.prototype.hasOwnProperty.call(obj, 'communities') && obj.communities !== undefined) {
    if (!Array.isArray(obj.communities)) {
      return err(`${ctx}.communities must be an array.`);
    }
    communities = [];
    for (let i = 0; i < obj.communities.length; i++) {
      const c = obj.communities[i];
      if (typeof c !== 'number' || !Number.isInteger(c) || c < 0 || c > 0xffffffff) {
        return err(`${ctx}.communities[${i}] must be a 32-bit unsigned integer.`);
      }
      communities.push(c);
    }
  }

  let largeCommunities: BgpLargeCommunity[] | undefined;
  if (
    Object.prototype.hasOwnProperty.call(obj, 'largeCommunities') &&
    obj.largeCommunities !== undefined
  ) {
    if (!Array.isArray(obj.largeCommunities)) {
      return err(`${ctx}.largeCommunities must be an array.`);
    }
    largeCommunities = [];
    for (let i = 0; i < obj.largeCommunities.length; i++) {
      const lcObj = validateAllowedKeys(
        obj.largeCommunities[i],
        ['globalAdmin', 'localData1', 'localData2'],
        [],
        `${ctx}.largeCommunities[${i}]`,
      );
      if (!lcObj.ok) return lcObj;
      const g = expectUint(lcObj.value, 'globalAdmin', 0xffffffff, `${ctx}.largeCommunities[${i}]`);
      const d1 = expectUint(lcObj.value, 'localData1', 0xffffffff, `${ctx}.largeCommunities[${i}]`);
      const d2 = expectUint(lcObj.value, 'localData2', 0xffffffff, `${ctx}.largeCommunities[${i}]`);
      if (!g.ok) return g;
      if (!d1.ok) return d1;
      if (!d2.ok) return d2;
      largeCommunities.push({ globalAdmin: g.value, localData1: d1.value, localData2: d2.value });
    }
  }

  return ok({
    id: id.value,
    prefix: prefix.value,
    origin: origin.value as BgpOriginValue,
    ...(med.value !== undefined ? { med: med.value } : {}),
    ...(localPref.value !== undefined ? { localPref: localPref.value } : {}),
    ...(communities !== undefined ? { communities } : {}),
    ...(largeCommunities !== undefined ? { largeCommunities } : {}),
  });
}

function validateRouterConfig(raw: unknown, ctx: string): Result<RouterConfig> {
  const objRes = validateAllowedKeys(
    raw,
    ['name', 'asn', 'routerId', 'holdTime', 'mac', 'peeringAddress', 'capabilities', 'routes'],
    ['expectedPeerAs', 'localPref', 'ipv6NextHop'],
    ctx,
  );
  if (!objRes.ok) return objRes;
  const obj = objRes.value;

  const name = expectString(obj, 'name', ctx);
  const asn = expectUint(obj, 'asn', 0xffffffff, ctx);
  const expectedPeerAs = expectOptionalUint(obj, 'expectedPeerAs', 0xffffffff, ctx);
  const routerId = expectString(obj, 'routerId', ctx);
  const holdTime = expectUint(obj, 'holdTime', 0xffff, ctx);
  const localPref = expectOptionalUint(obj, 'localPref', 0xffffffff, ctx);
  const mac = expectString(obj, 'mac', ctx);
  const peeringAddress = expectString(obj, 'peeringAddress', ctx);
  const ipv6NextHop = expectOptionalString(obj, 'ipv6NextHop', ctx);
  const capabilities = validateCapabilities(obj.capabilities, `${ctx}.capabilities`);
  if (!name.ok) return name;
  if (!asn.ok) return asn;
  if (asn.value < 1) return err(`${ctx}.asn must be >= 1.`);
  if (!expectedPeerAs.ok) return expectedPeerAs;
  if (!routerId.ok) return routerId;
  if (!holdTime.ok) return holdTime;
  if (!localPref.ok) return localPref;
  if (!mac.ok) return mac;
  if (!peeringAddress.ok) return peeringAddress;
  if (!ipv6NextHop.ok) return ipv6NextHop;
  if (!capabilities.ok) return capabilities;

  if (!Array.isArray(obj.routes) || obj.routes.length > MAX_SESSION_ROUTES) {
    return err(`${ctx}.routes must be an array of at most ${MAX_SESSION_ROUTES} routes.`);
  }
  const routes: OriginatedRoute[] = [];
  for (let i = 0; i < obj.routes.length; i++) {
    const r = validateRoute(obj.routes[i], `${ctx}.routes[${i}]`);
    if (!r.ok) return r;
    routes.push(r.value);
  }

  return ok({
    name: name.value,
    asn: asn.value,
    ...(expectedPeerAs.value !== undefined ? { expectedPeerAs: expectedPeerAs.value } : {}),
    routerId: routerId.value,
    holdTime: holdTime.value,
    ...(localPref.value !== undefined ? { localPref: localPref.value } : {}),
    mac: mac.value,
    peeringAddress: peeringAddress.value,
    ...(ipv6NextHop.value !== undefined ? { ipv6NextHop: ipv6NextHop.value } : {}),
    capabilities: capabilities.value,
    routes,
  });
}

function expectOptionalStringArray(
  obj: Record<string, unknown>,
  key: string,
  ctx: string,
): Result<readonly string[] | undefined> {
  if (!Object.prototype.hasOwnProperty.call(obj, key) || obj[key] === undefined) {
    return ok(undefined);
  }
  const raw = obj[key];
  if (!Array.isArray(raw) || raw.some((item) => typeof item !== 'string')) {
    return err(`${ctx}.${key} must be an array of strings.`);
  }
  return ok(raw as string[]);
}

function validateEvent(raw: unknown, ctx: string): Result<SessionEvent> {
  if (!isPlainObject(raw)) return err(`${ctx} must be an object.`);
  const type = raw.type;
  switch (type) {
    case 'establish': {
      const check = validateAllowedKeys(raw, ['type'], [], ctx);
      if (!check.ok) return check;
      return ok({ type: 'establish' });
    }
    case 'advertise':
    case 'withdraw': {
      const check = validateAllowedKeys(raw, ['type', 'router'], ['routeIds', 'prefixes'], ctx);
      if (!check.ok) return check;
      const router = expectRouterId(check.value, 'router', ctx);
      const routeIds = expectOptionalStringArray(check.value, 'routeIds', ctx);
      const prefixes = expectOptionalStringArray(check.value, 'prefixes', ctx);
      if (!router.ok) return router;
      if (!routeIds.ok) return routeIds;
      if (!prefixes.ok) return prefixes;
      return ok({
        type,
        router: router.value,
        ...(routeIds.value !== undefined ? { routeIds: routeIds.value } : {}),
        ...(prefixes.value !== undefined ? { prefixes: prefixes.value } : {}),
      });
    }
    case 'endOfRib': {
      const check = validateAllowedKeys(raw, ['type'], ['router'], ctx);
      if (!check.ok) return check;
      if (Object.prototype.hasOwnProperty.call(check.value, 'router') && check.value.router !== undefined) {
        const router = expectRouterId(check.value, 'router', ctx);
        if (!router.ok) return router;
        return ok({ type: 'endOfRib', router: router.value });
      }
      return ok({ type: 'endOfRib' });
    }
    case 'holdTimerExpires':
    case 'adminShutdown': {
      const check = validateAllowedKeys(raw, ['type', 'router'], [], ctx);
      if (!check.ok) return check;
      const router = expectRouterId(check.value, 'router', ctx);
      if (!router.ok) return router;
      return ok({ type, router: router.value });
    }
    default:
      return err(`${ctx}.type "${String(type)}" is not a supported session event.`);
  }
}

/**
 * Strictly decodes and validates a `#s1=` BGP session permalink fragment.
 * Prototype-pollution safe; never throws on malformed or hostile input.
 */
export function decodeSessionPermalink(fragmentOrHash: string): Result<SessionPermalinkState> {
  const trimmed = fragmentOrHash.startsWith('#') ? fragmentOrHash.slice(1) : fragmentOrHash;
  const match = FRAGMENT_VERSION_PATTERN.exec(trimmed);
  if (!match) {
    return err('Unrecognized permalink format. Expected #s1=<data>.');
  }
  const version = Number.parseInt(match[1], 10);
  if (version !== SESSION_PERMALINK_VERSION) {
    return err(`Unsupported session permalink version s${version}.`);
  }

  const rawBytes = base64UrlToBytes(match[2]);
  if (!rawBytes.ok) return rawBytes;

  const jsonText = decodeUtf8Strict(rawBytes.value);
  if (!jsonText.ok) return err('Permalink payload is not valid UTF-8.');

  // Quick pre-check for raw "__proto__" property tokens before JSON.parse drops/alters them
  if (/"(?:__proto__|constructor|prototype)"\s*:/.test(jsonText.value)) {
    return err('Permalink JSON contains forbidden prototype key.');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText.value);
  } catch {
    return err('Permalink payload is not valid JSON.');
  }

  const safeCheck = checkNoForbiddenKeysRecursive(parsed);
  if (!safeCheck.ok) return safeCheck;

  const rootRes = validateAllowedKeys(parsed, ['scenarioId', 'config', 'events'], [], 'root');
  if (!rootRes.ok) return rootRes;

  const scenarioId = expectString(rootRes.value, 'scenarioId', 'root');
  if (!scenarioId.ok) return scenarioId;

  const configObj = validateAllowedKeys(
    rootRes.value.config,
    ['routerA', 'routerB'],
    ['baseTimestampMs'],
    'config',
  );
  if (!configObj.ok) return configObj;

  const routerA = validateRouterConfig(configObj.value.routerA, 'config.routerA');
  const routerB = validateRouterConfig(configObj.value.routerB, 'config.routerB');
  const baseTs = expectOptionalUint(configObj.value, 'baseTimestampMs', Number.MAX_SAFE_INTEGER, 'config');
  if (!routerA.ok) return routerA;
  if (!routerB.ok) return routerB;
  if (!baseTs.ok) return baseTs;

  if (!Array.isArray(rootRes.value.events) || rootRes.value.events.length > MAX_SESSION_EVENTS) {
    return err(`events must be an array of at most ${MAX_SESSION_EVENTS} events.`);
  }
  const events: SessionEvent[] = [];
  for (let i = 0; i < rootRes.value.events.length; i++) {
    const ev = validateEvent(rootRes.value.events[i], `events[${i}]`);
    if (!ev.ok) return ev;
    events.push(ev.value);
  }

  return ok({
    scenarioId: scenarioId.value,
    config: {
      routerA: routerA.value,
      routerB: routerB.value,
      ...(baseTs.value !== undefined ? { baseTimestampMs: baseTs.value } : {}),
    },
    events,
  });
}
