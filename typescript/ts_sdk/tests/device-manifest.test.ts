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
  parseDeviceManifest,
  removeDeviceFromDidDocument,
  updateDeviceInDidDocument,
  validateDeviceManifest,
} from '../src/index.js';

const testdataDir = join(
  dirname(fileURLToPath(import.meta.url)),
  '../../../testdata/device_manifest'
);

function loadJson(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(testdataDir, name), 'utf8')) as Record<string, unknown>;
}

describe('Device Manifest fixtures', () => {
  const fixtures = loadJson('vnext_device_manifest_fixtures.json');
  const base = fixtures.base_did_document as Record<string, unknown>;
  const valid = fixtures.valid as Array<Record<string, unknown>>;
  const invalid = fixtures.invalid as Array<Record<string, unknown>>;

  function buildDocument(caseRecord: Record<string, unknown>): Record<string, unknown> {
    const document = structuredClone(base);
    Object.assign(
      document,
      structuredClone((caseRecord.document_patch ?? {}) as Record<string, unknown>)
    );
    document.deviceManifest = structuredClone(caseRecord.device_manifest);
    return document;
  }

  test.each(valid.map((item) => [item.name, item] as const))(
    'accepts valid case %s',
    (_name, caseRecord) => {
      const document = buildDocument(caseRecord);
      const before = structuredClone(document);
      const parsed = parseDeviceManifest(document);
      expect(parsed).not.toBeNull();
      expect(parsed?.toDict()).toEqual(caseRecord.device_manifest);
      expect(validateDeviceManifest(document)?.toDict()).toEqual(parsed?.toDict());
      const lookup = caseRecord.lookup as { device_id: string; profile: string; found: boolean };
      const device = findEligibleDevice(document, lookup.device_id, lookup.profile);
      expect(device !== null).toBe(lookup.found);
      expect(document).toEqual(before);
      expect(
        (document['x-fixture-extension'] as { must_survive_validation: boolean })
          .must_survive_validation
      ).toBe(true);
      const wire = JSON.stringify(parsed?.toDict());
      expect(wire).toContain('"device_id"');
      expect(wire).toContain('"signing_key_id"');
      expect(wire).toContain('"e2ee_key_id"');
      expect(wire).toContain('"profiles"');
      expect(wire).not.toContain('"deviceId"');
      expect(wire).not.toContain('"signingKeyId"');
      expect(wire).not.toContain('"e2eeKeyId"');
    }
  );

  test.each(invalid.map((item) => [item.name, item] as const))(
    'rejects invalid case %s',
    (_name, caseRecord) => {
      const document = buildDocument(caseRecord);
      expect(() => validateDeviceManifest(document)).toThrow(DeviceManifestError);
    }
  );

  test('missing manifest is valid and does not invent a device', () => {
    const document = structuredClone(base);
    expect(parseDeviceManifest(document)).toBeNull();
    expect(validateDeviceManifest(document)).toBeNull();
    expect(findEligibleDevice(document, 'dev-a-7N3KQ2', 'anp.direct.e2ee.v2')).toBeNull();
  });
});

describe('vNext DID builder fixtures', () => {
  const fixture = loadJson('vnext_did_builder_fixtures.json');

  function entry(deviceFixture: Record<string, unknown>): DeviceManifestEntry {
    const value = deviceFixture.entry as {
      device_id: string;
      signing_key_id: string;
      e2ee_key_id: string;
      profiles: string[];
    };
    return DeviceManifestEntry.fromWire(value);
  }

  function build(): Record<string, unknown> {
    const device = fixture.device_a as Record<string, unknown>;
    return buildVnextDidDocument(
      fixture.base_document as Record<string, unknown>,
      fixture.root_key_id as string,
      fixture.root_verification_method as Record<string, unknown>,
      entry(device),
      device.signing_verification_method as Record<string, unknown>,
      device.e2ee_verification_method as Record<string, unknown>
    );
  }

  test('build/add/update/remove match shared vectors and keep snake_case wire keys', () => {
    const baseBefore = structuredClone(fixture.base_document);
    const built = build();
    expect(built).toEqual(fixture.expected_build);
    expect(fixture.base_document).toEqual(baseBefore);
    expect(built['x-example']).toEqual(
      (fixture.base_document as Record<string, unknown>)['x-example']
    );

    const wire = JSON.stringify((built.deviceManifest as { devices: unknown[] }).devices);
    expect(wire).toContain('"device_id"');
    expect(wire).not.toContain('"deviceId"');

    const withStaleProof = { ...built, proof: { proofValue: 'stale' } };
    const deviceB = fixture.device_b as Record<string, unknown>;
    const added = addDeviceToDidDocument(
      withStaleProof,
      fixture.root_key_id as string,
      entry(deviceB),
      deviceB.signing_verification_method as Record<string, unknown>,
      deviceB.e2ee_verification_method as Record<string, unknown>,
      fixture.retired_device_ids as string[]
    );
    expect(added).toEqual(fixture.expected_add);
    expect(added.proof).toBeUndefined();
    expect(withStaleProof.proof).toEqual({ proofValue: 'stale' });

    const rotated = fixture.device_b_rotated as Record<string, unknown>;
    const updated = updateDeviceInDidDocument(
      added,
      fixture.root_key_id as string,
      entry(rotated),
      rotated.signing_verification_method as Record<string, unknown>,
      rotated.e2ee_verification_method as Record<string, unknown>
    );
    expect(updated).toEqual(fixture.expected_update);

    const removed = removeDeviceFromDidDocument(
      updated,
      fixture.root_key_id as string,
      (rotated.entry as { device_id: string }).device_id
    );
    expect(removed).toEqual(fixture.expected_remove);
    expect((removed.deviceManifest as { devices: unknown[] }).devices).toEqual(
      (built.deviceManifest as { devices: unknown[] }).devices
    );
    expect(validateDeviceManifest(removed)).not.toBeNull();
  });

  test('rejects root-as-device-key and private key material', () => {
    const device = structuredClone(fixture.device_a) as Record<string, unknown>;
    const deviceEntry = structuredClone(device.entry) as Record<string, unknown>;
    deviceEntry.signing_key_id = fixture.root_key_id;
    device.entry = deviceEntry;
    device.signing_verification_method = structuredClone(fixture.root_verification_method);
    expect(() =>
      buildVnextDidDocument(
        fixture.base_document as Record<string, unknown>,
        fixture.root_key_id as string,
        fixture.root_verification_method as Record<string, unknown>,
        entry(device),
        device.signing_verification_method as Record<string, unknown>,
        device.e2ee_verification_method as Record<string, unknown>
      )
    ).toThrow(/root key/);

    const privateRoot = structuredClone(fixture.root_verification_method) as Record<
      string,
      unknown
    >;
    const jwk = structuredClone(privateRoot.publicKeyJwk) as Record<string, unknown>;
    jwk.d = 'PRIVATE';
    privateRoot.publicKeyJwk = jwk;
    expect(() =>
      buildVnextDidDocument(
        fixture.base_document as Record<string, unknown>,
        fixture.root_key_id as string,
        privateRoot,
        entry(fixture.device_a as Record<string, unknown>),
        (fixture.device_a as Record<string, unknown>).signing_verification_method as Record<
          string,
          unknown
        >,
        (fixture.device_a as Record<string, unknown>).e2ee_verification_method as Record<
          string,
          unknown
        >
      )
    ).toThrow(/private key/);
  });
});
