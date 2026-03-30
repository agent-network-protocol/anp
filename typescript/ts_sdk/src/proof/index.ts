export * from './proof.js';

export {
  generateW3cProof as createProof,
  verifyW3cProof as verifyProof,
  verifyW3cProofDetailed as verifyProofDetailed,
} from './proof.js';

import {
  generateW3cProof,
  verifyW3cProof,
  verifyW3cProofDetailed,
} from './proof.js';

export const proof = {
  create: generateW3cProof,
  verify: verifyW3cProof,
  verifyDetailed: verifyW3cProofDetailed,
};
