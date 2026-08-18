import * as sdk from '../dist/index.js';

const expectedFunctions = [
  'DeviceManifestEntry',
  'buildVnextDidDocument',
  'generateRfc9421OriginProof',
  'validateDeviceManifest',
];

const expectedConstants = {
  PROFILE_CORE_BINDING_V1: 'anp.core.binding.v1',
  PROFILE_DIRECT_BASE_V1: 'anp.direct.base.v1',
  PROFILE_DIRECT_E2EE_V2: 'anp.direct.e2ee.v2',
  PROFILE_GROUP_BASE_V1: 'anp.group.base.v1',
  PROFILE_GROUP_E2EE_V2: 'anp.group.e2ee.v2',
  PROFILE_IDENTITY_DISCOVERY_V1: 'anp.identity.discovery.v1',
};

const failures = [];
for (const name of expectedFunctions) {
  if (typeof sdk[name] !== 'function') {
    failures.push(`${name} must be a function`);
  }
}
for (const [name, expected] of Object.entries(expectedConstants)) {
  if (sdk[name] !== expected) {
    failures.push(`${name} must equal ${JSON.stringify(expected)}`);
  }
}

if (failures.length > 0) {
  throw new Error(`built package export check failed:\n${failures.join('\n')}`);
}

console.log(
  `Verified ${expectedFunctions.length + Object.keys(expectedConstants).length} Lite SDK exports.`
);
