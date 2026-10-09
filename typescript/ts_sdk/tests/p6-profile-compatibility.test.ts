import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, test } from 'vitest';

import {
  DeviceManifestEntry,
  DeviceManifestError,
  addDeviceToDidDocument,
  buildVnextDidDocument,
  findEligibleDevice,
  removeDeviceFromDidDocument,
  updateDeviceInDidDocument,
  validateDeviceManifest,
} from '../src/index.js';

interface DeviceFixture {
  entry: {
    device_id: string;
    signing_key_id: string;
    e2ee_key_id: string;
    profiles: string[];
  };
  signing_verification_method: Record<string, unknown>;
  e2ee_verification_method: Record<string, unknown>;
}

const fixture = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      '../../../testdata/device_manifest/vnext_did_builder_fixtures.json'
    ),
    'utf8'
  )
) as Record<string, unknown>;
const rootKeyId = fixture.root_key_id as string;
const currentP6 = [
  'anp.core.binding.v1',
  'anp.identity.discovery.v1',
  'anp.group.base.v2',
  'anp.group.e2ee.v2',
];
const legacyBundles = [
  {
    name: 'legacy mixed',
    profiles: [
      'anp.core.binding.v1',
      'anp.identity.discovery.v1',
      'anp.group.base.v1',
      'anp.group.e2ee.v2',
    ],
  },
  {
    name: 'legacy all-v2',
    profiles: [
      'anp.core.binding.v2',
      'anp.identity.discovery.v2',
      'anp.group.base.v2',
      'anp.group.e2ee.v2',
    ],
  },
];

function device(name: string, profiles: string[] = currentP6): DeviceFixture {
  const value = structuredClone(fixture[name]) as DeviceFixture;
  value.entry.profiles = [...profiles];
  return value;
}

function build(value: DeviceFixture = device('device_a')): Record<string, unknown> {
  return buildVnextDidDocument(
    fixture.base_document as Record<string, unknown>,
    rootKeyId,
    fixture.root_verification_method as Record<string, unknown>,
    DeviceManifestEntry.fromWire(value.entry),
    value.signing_verification_method,
    value.e2ee_verification_method
  );
}

function add(document: Record<string, unknown>, value: DeviceFixture): unknown {
  return addDeviceToDidDocument(
    document,
    rootKeyId,
    DeviceManifestEntry.fromWire(value.entry),
    value.signing_verification_method,
    value.e2ee_verification_method,
    fixture.retired_device_ids as string[]
  );
}

function update(document: Record<string, unknown>, value: DeviceFixture): unknown {
  return updateDeviceInDidDocument(
    document,
    rootKeyId,
    DeviceManifestEntry.fromWire(value.entry),
    value.signing_verification_method,
    value.e2ee_verification_method
  );
}

describe('P6 profile write contract', () => {
  test.each([
    ['current P6', currentP6],
    ['current P6 with explicit base.v1', [...currentP6, 'anp.group.base.v1']],
    [
      'unchanged P5',
      [
        'anp.core.binding.v1',
        'anp.identity.discovery.v1',
        'anp.direct.base.v1',
        'anp.direct.e2ee.v2',
      ],
    ],
    ['ordinary Base v1', ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.group.base.v1']],
    ['ordinary Base v2', ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.group.base.v2']],
  ])('publishes %s without changing its capabilities', (_name, profiles) => {
    const input = device('device_a', profiles);
    const before = structuredClone(input);
    const document = build(input);
    expect(validateDeviceManifest(document)?.devices[0]?.profiles).toEqual(profiles);
    if (profiles.includes('anp.group.e2ee.v2')) {
      expect(
        findEligibleDevice(document, input.entry.device_id, 'anp.group.e2ee.v2')
      ).not.toBeNull();
    }
    expect(input).toEqual(before);
  });

  test.each(currentP6.slice(0, 3))('rejects current P6 missing %s', (missing) => {
    expect(() =>
      build(
        device(
          'device_a',
          currentP6.filter((p) => p !== missing)
        )
      )
    ).toThrow(DeviceManifestError);
  });

  test.each(['anp.core.binding.v1', 'anp.identity.discovery.v1'])(
    'rejects ordinary Base v2 missing %s',
    (missing) => {
      const profiles = currentP6.filter(
        (profile) => profile !== 'anp.group.e2ee.v2' && profile !== missing
      );
      expect(() => build(device('device_a', profiles))).toThrow(DeviceManifestError);
    }
  );

  test.each(legacyBundles)(
    'reads $name and requires canonical mutation results without mutating inputs',
    ({ profiles }) => {
      const current = build();
      const currentBefore = structuredClone(current);
      const legacyA = device('device_a', profiles);
      const legacyB = device('device_b', profiles);
      const legacyBefore = structuredClone(legacyA);
      const legacyDocument = structuredClone(current);
      const manifest = legacyDocument.deviceManifest as { devices: DeviceFixture['entry'][] };
      const directBase = profiles.includes('anp.core.binding.v2')
        ? 'anp.direct.base.v2'
        : 'anp.direct.base.v1';
      manifest.devices[0] = {
        ...manifest.devices[0],
        profiles: [...profiles, directBase, 'anp.direct.e2ee.v2'],
      };
      legacyDocument.proof = { proofValue: 'preserve-on-rejection' };
      const legacyDocumentBefore = structuredClone(legacyDocument);

      expect(validateDeviceManifest(legacyDocument)).not.toBeNull();
      expect(
        findEligibleDevice(legacyDocument, legacyA.entry.device_id, 'anp.group.e2ee.v2')
      ).toBeNull();
      expect(
        findEligibleDevice(legacyDocument, legacyA.entry.device_id, 'anp.direct.e2ee.v2')
      ).not.toBeNull();
      const writes = [
        () => build(legacyA),
        () => add(current, legacyB),
        () => update(current, legacyA),
        () => add(legacyDocument, device('device_b')),
      ];
      for (const write of writes) {
        expect(write).toThrow(/P6 legacy dependency bundles are read-only/);
      }
      expect(update(legacyDocument, device('device_a'))).toEqual(current);
      const mixedDocument = add(current, device('device_b')) as Record<string, unknown>;
      const mixedManifest = mixedDocument.deviceManifest as { devices: DeviceFixture['entry'][] };
      mixedManifest.devices[1].profiles = [...profiles];
      mixedDocument.proof = { proofValue: 'preserve-input-proof' };
      const mixedBefore = structuredClone(mixedDocument);
      expect(
        removeDeviceFromDidDocument(mixedDocument, rootKeyId, legacyB.entry.device_id)
      ).toEqual(current);
      // Unrelated mutations must not republish a remaining historical entry.
      expect(() => update(mixedDocument, device('device_a'))).toThrow(DeviceManifestError);
      expect(() =>
        removeDeviceFromDidDocument(mixedDocument, rootKeyId, legacyA.entry.device_id)
      ).toThrow(DeviceManifestError);
      expect(mixedDocument).toEqual(mixedBefore);
      expect(current).toEqual(currentBefore);
      expect(legacyDocument).toEqual(legacyDocumentBefore);
      expect(legacyA).toEqual(legacyBefore);
    }
  );
});
