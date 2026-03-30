export * from './types.js';
export * from './validator.js';
export * from './resolver.js';
export * from './binding.js';

export {
  parseWbaUri as parseUri,
  buildWbaUri as buildUri,
} from './validator.js';
export { resolveHandleFromUri as resolveUri } from './resolver.js';
export {
  verifyHandleBinding as verifyBinding,
  buildHandleServiceEntry as createHandleServiceEntry,
  extractHandleServiceFromDidDocument as extractHandleServices,
} from './binding.js';

import {
  validateLocalPart,
  validateHandle,
  normalizeHandle,
  parseWbaUri,
  buildResolutionUrl,
  buildWbaUri,
} from './validator.js';
import { resolveHandle, resolveHandleFromUri } from './resolver.js';
import {
  verifyHandleBinding,
  buildHandleServiceEntry,
  extractHandleServiceFromDidDocument,
} from './binding.js';

export const wns = {
  validateLocalPart,
  validateHandle,
  normalizeHandle,
  parseUri: parseWbaUri,
  buildResolutionUrl,
  buildUri: buildWbaUri,
  resolveHandle,
  resolveUri: resolveHandleFromUri,
  verifyBinding: verifyHandleBinding,
  createHandleServiceEntry: buildHandleServiceEntry,
  extractHandleServices: extractHandleServiceFromDidDocument,
};
