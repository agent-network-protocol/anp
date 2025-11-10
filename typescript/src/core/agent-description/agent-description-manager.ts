/**
 * Agent Description Manager for creating and managing agent descriptions
 */

import canonicalize from 'canonicalize';
import type {
  AgentDescription,
  AgentMetadata,
  Information,
  Interface,
  DIDIdentity,
  Proof,
} from '../../types/index.js';
import type { DIDManager } from '../did/did-manager.js';
import { decodeSignature, encodeSignature } from '../../crypto/signing.js';

/**
 * Agent Description Manager class
 */
export class AgentDescriptionManager {
  /**
   * Create a new agent description
   *
   * @param metadata - Agent metadata
   * @returns Agent description document
   * @throws {Error} If validation fails
   */
  createDescription(metadata: AgentMetadata): AgentDescription {
    // Validate required fields
    this.validateMetadata(metadata);

    // Create agent description
    const description: AgentDescription = {
      protocolType: 'ANP',
      protocolVersion: metadata.protocolVersion ?? '1.0.0',
      type: 'AgentDescription',
      name: metadata.name,
      created: new Date().toISOString(),
      securityDefinitions: {
        did_wba: {
          scheme: 'did_wba',
          type: 'http',
          description: 'DID-based authentication using did:wba method',
        },
      },
      security: 'did_wba',
      Infomations: [],
      interfaces: [],
    };

    // Add optional fields
    if (metadata.did) {
      description.did = metadata.did;
    }

    if (metadata.owner) {
      description.owner = metadata.owner;
    }

    if (metadata.description) {
      description.description = metadata.description;
    }

    if (metadata.url) {
      description.url = metadata.url;
    }

    return description;
  }

  /**
   * Add information resource to agent description
   *
   * @param description - Agent description
   * @param info - Information resource to add
   * @returns Updated agent description
   * @throws {Error} If validation fails or duplicate URL exists
   */
  addInformation(
    description: AgentDescription,
    info: Information
  ): AgentDescription {
    // Validate information resource
    this.validateInformation(info);

    // Check for duplicate URL
    if (description.Infomations?.some((i) => i.url === info.url)) {
      throw new Error(
        `Information resource with URL ${info.url} already exists`
      );
    }

    // Create updated description
    return {
      ...description,
      Infomations: [...(description.Infomations ?? []), info],
    };
  }

  /**
   * Add interface to agent description
   *
   * @param description - Agent description
   * @param iface - Interface to add
   * @returns Updated agent description
   * @throws {Error} If validation fails or duplicate URL exists
   */
  addInterface(
    description: AgentDescription,
    iface: Interface
  ): AgentDescription {
    // Validate interface
    this.validateInterface(iface);

    // Check for duplicate URL
    if (description.interfaces?.some((i) => i.url === iface.url)) {
      throw new Error(`Interface with URL ${iface.url} already exists`);
    }

    // Create updated description
    return {
      ...description,
      interfaces: [...(description.interfaces ?? []), iface],
    };
  }

  /**
   * Validate agent metadata
   *
   * @param metadata - Agent metadata to validate
   * @throws {Error} If validation fails
   */
  private validateMetadata(metadata: AgentMetadata): void {
    if (!metadata.name || metadata.name.trim() === '') {
      throw new Error('Agent name is required');
    }
  }

  /**
   * Validate information resource
   *
   * @param info - Information resource to validate
   * @throws {Error} If validation fails
   */
  private validateInformation(info: Information): void {
    if (!info.type || !info.description || !info.url) {
      throw new Error(
        'Information resource must have type, description, and url'
      );
    }
  }

  /**
   * Validate interface
   *
   * @param iface - Interface to validate
   * @throws {Error} If validation fails
   */
  private validateInterface(iface: Interface): void {
    if (!iface.type || !iface.protocol || !iface.version || !iface.url) {
      throw new Error('Interface must have type, protocol, version, and url');
    }
  }

  /**
   * Sign agent description
   *
   * @param description - Agent description to sign
   * @param identity - DID identity to sign with
   * @param challenge - Challenge string
   * @param domain - Domain for proof
   * @returns Signed agent description with proof
   * @throws {Error} If signing fails
   */
  async signDescription(
    description: AgentDescription,
    identity: DIDIdentity,
    challenge: string,
    domain: string
  ): Promise<AgentDescription> {
    // Validate that description has a DID
    if (!description.did) {
      throw new Error('Agent description must have a DID to be signed');
    }

    // Create a copy without proof for signing
    const { proof, ...descriptionWithoutProof } = description;

    // Canonicalize the description using JCS
    const canonicalJson = canonicalize(descriptionWithoutProof);
    if (!canonicalJson) {
      throw new Error('Failed to canonicalize agent description');
    }

    // Convert to bytes
    const dataToSign = new TextEncoder().encode(canonicalJson);

    // Sign the data
    const { DIDManager } = await import('../did/did-manager.js');
    const didManager = new DIDManager();
    const signature = await didManager.sign(identity, dataToSign);

    // Create proof object
    const proofObj: Proof = {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: signature.verificationMethod,
      proofPurpose: 'authentication',
      challenge,
      domain,
      proofValue: encodeSignature(signature.value),
    };

    // Return description with proof
    return {
      ...description,
      proof: proofObj,
    };
  }

  /**
   * Verify agent description signature
   *
   * @param description - Agent description with proof
   * @param didManager - DID manager for verification
   * @param didDocument - Optional DID document (to avoid resolution)
   * @returns True if signature is valid, false otherwise
   */
  async verifyDescription(
    description: AgentDescription,
    didManager: DIDManager,
    didDocument?: any
  ): Promise<boolean> {
    // Check if description has proof
    if (!description.proof) {
      return false;
    }

    // Check if description has DID
    if (!description.did) {
      return false;
    }

    try {
      // Extract proof
      const { proof, ...descriptionWithoutProof } = description;

      // Canonicalize the description
      const canonicalJson = canonicalize(descriptionWithoutProof);
      if (!canonicalJson) {
        return false;
      }

      // Convert to bytes
      const dataToVerify = new TextEncoder().encode(canonicalJson);

      // Decode signature
      const signatureValue = decodeSignature(proof.proofValue);

      // Verify signature (pass didDocument if provided to avoid resolution)
      const isValid = await didManager.verify(
        description.did,
        dataToVerify,
        {
          value: signatureValue,
          verificationMethod: proof.verificationMethod,
        },
        didDocument
      );

      return isValid;
    } catch (error) {
      return false;
    }
  }

  /**
   * Fetch agent description from URL
   *
   * @param url - URL to fetch agent description from
   * @returns Agent description
   * @throws {Error} If fetching or parsing fails
   */
  async fetchDescription(url: string): Promise<AgentDescription> {
    try {
      // Fetch the description
      const response = await fetch(url, {
        headers: {
          Accept: 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(
          `Failed to fetch agent description: HTTP ${response.status} ${response.statusText}`
        );
      }

      // Parse JSON
      let description: any;
      try {
        description = await response.json();
      } catch (error) {
        throw new Error(
          `Failed to parse agent description: ${(error as Error).message}`
        );
      }

      // Validate description
      this.validateAgentDescription(description);

      return description as AgentDescription;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Failed to fetch agent description');
    }
  }

  /**
   * Validate agent description structure
   *
   * @param description - Description to validate
   * @throws {Error} If validation fails
   */
  private validateAgentDescription(description: any): void {
    if (!description.protocolType || description.protocolType !== 'ANP') {
      throw new Error(
        'Invalid agent description: protocolType must be "ANP"'
      );
    }

    if (!description.type || description.type !== 'AgentDescription') {
      throw new Error(
        'Invalid agent description: type must be "AgentDescription"'
      );
    }

    if (!description.name) {
      throw new Error('Invalid agent description: name is required');
    }

    if (!description.securityDefinitions) {
      throw new Error(
        'Invalid agent description: securityDefinitions is required'
      );
    }

    if (!description.security) {
      throw new Error('Invalid agent description: security is required');
    }
  }

  /**
   * Verify agent description with domain validation
   *
   * @param description - Agent description with proof
   * @param didManager - DID manager for verification
   * @param expectedDomain - Expected domain in proof
   * @param didDocument - Optional DID document (to avoid resolution)
   * @returns True if signature is valid and domain matches, false otherwise
   */
  async verifyDescriptionWithDomain(
    description: AgentDescription,
    didManager: DIDManager,
    expectedDomain: string,
    didDocument?: any
  ): Promise<boolean> {
    // First verify the signature
    const isSignatureValid = await this.verifyDescription(
      description,
      didManager,
      didDocument
    );

    if (!isSignatureValid) {
      return false;
    }

    // Check domain
    if (description.proof?.domain !== expectedDomain) {
      return false;
    }

    return true;
  }

  /**
   * Verify agent description with challenge validation
   *
   * @param description - Agent description with proof
   * @param didManager - DID manager for verification
   * @param expectedChallenge - Expected challenge in proof
   * @param didDocument - Optional DID document (to avoid resolution)
   * @returns True if signature is valid and challenge matches, false otherwise
   */
  async verifyDescriptionWithChallenge(
    description: AgentDescription,
    didManager: DIDManager,
    expectedChallenge: string,
    didDocument?: any
  ): Promise<boolean> {
    // First verify the signature
    const isSignatureValid = await this.verifyDescription(
      description,
      didManager,
      didDocument
    );

    if (!isSignatureValid) {
      return false;
    }

    // Check challenge
    if (description.proof?.challenge !== expectedChallenge) {
      return false;
    }

    return true;
  }
}
