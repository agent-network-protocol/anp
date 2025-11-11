/**
 * Agent Discovery Example
 * 
 * This example demonstrates agent discovery:
 * - Active discovery from domains
 * - Passive discovery via search services
 * - Fetching agent descriptions
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  console.log('=== Agent Discovery Example ===\n');

  const client = new ANPClient({ debug: false });

  // Step 1: Create agent identity
  console.log('Step 1: Creating agent identity...');
  const identity = await client.did.create({
    domain: 'my-agent.example.com',
    path: 'discoverer',
  });
  console.log('Created DID:', identity.did);
  console.log('');

  // Step 2: Create and publish agent description
  console.log('Step 2: Creating agent description...');
  let description = client.agent.createDescription({
    name: 'Discovery Agent',
    description: 'An agent that discovers other agents',
    protocolVersion: '0.1.0',
    did: identity.did,
  });

  description = client.agent.addInterface(description, {
    type: 'Interface',
    protocol: 'HTTP',
    version: '1.1',
    url: 'https://my-agent.example.com/api',
  });

  const signedDescription = await client.agent.signDescription(
    description,
    identity,
    'discovery-challenge',
    'my-agent.example.com'
  );

  console.log('Agent description created and signed');
  console.log('');

  // Step 3: Active Discovery - Discover agents from a domain
  console.log('Step 3: Active Discovery...');
  console.log('Discovering agents from a domain...');
  console.log('');
  console.log('Example: Discovering from "example.com"');
  console.log('This would fetch: https://example.com/.well-known/agent-descriptions');
  console.log('');
  
  // In a real scenario with a live domain:
  // try {
  //   const agents = await client.discovery.discoverAgents('example.com', identity);
  //   console.log(`Found ${agents.length} agents:`);
  //   agents.forEach(agent => {
  //     console.log(`  - ${agent.name}: ${agent['@id']}`);
  //   });
  // } catch (error) {
  //   console.error('Discovery failed:', error.message);
  // }

  console.log('Active discovery process:');
  console.log('1. Fetch /.well-known/agent-descriptions from domain');
  console.log('2. Parse CollectionPage document');
  console.log('3. Extract agent description items');
  console.log('4. Follow pagination links if present');
  console.log('5. Return all discovered agents');
  console.log('');

  // Step 4: Passive Discovery - Register with search service
  console.log('Step 4: Passive Discovery - Registration...');
  console.log('Registering with a search service...');
  console.log('');
  
  const agentDescriptionUrl = 'https://my-agent.example.com/description.json';
  const searchServiceUrl = 'https://search.anp-network.com';
  
  console.log('Agent Description URL:', agentDescriptionUrl);
  console.log('Search Service URL:', searchServiceUrl);
  console.log('');
  
  // In a real scenario:
  // try {
  //   await client.discovery.registerWithSearchService(
  //     searchServiceUrl,
  //     agentDescriptionUrl,
  //     identity
  //   );
  //   console.log('✓ Successfully registered with search service');
  // } catch (error) {
  //   console.error('Registration failed:', error.message);
  // }

  console.log('Registration process:');
  console.log('1. Prepare registration request with agent description URL');
  console.log('2. Sign request with agent DID');
  console.log('3. Send POST request to search service');
  console.log('4. Search service validates and indexes the agent');
  console.log('');

  // Step 5: Search for agents
  console.log('Step 5: Searching for agents...');
  console.log('');
  
  const searchQuery = {
    keywords: 'translation',
    capabilities: ['text', 'language'],
  };
  
  console.log('Search query:', searchQuery);
  console.log('');
  
  // In a real scenario:
  // try {
  //   const results = await client.discovery.searchAgents(
  //     searchServiceUrl,
  //     searchQuery,
  //     identity
  //   );
  //   console.log(`Found ${results.length} matching agents:`);
  //   results.forEach(agent => {
  //     console.log(`  - ${agent.name}: ${agent['@id']}`);
  //   });
  // } catch (error) {
  //   console.error('Search failed:', error.message);
  // }

  console.log('Search process:');
  console.log('1. Construct search query with filters');
  console.log('2. Send query to search service');
  console.log('3. Receive matching agent descriptions');
  console.log('4. Optionally fetch full descriptions');
  console.log('');

  // Step 6: Fetch agent description
  console.log('Step 6: Fetching agent description...');
  console.log('');
  
  const exampleAgentUrl = 'https://other-agent.example.com/description.json';
  console.log('Fetching from:', exampleAgentUrl);
  console.log('');
  
  // In a real scenario:
  // try {
  //   const fetchedDescription = await client.agent.fetchDescription(exampleAgentUrl);
  //   console.log('Fetched agent:', fetchedDescription.name);
  //   console.log('Description:', fetchedDescription.description);
  //   console.log('Interfaces:', fetchedDescription.interfaces?.length || 0);
  // } catch (error) {
  //   console.error('Fetch failed:', error.message);
  // }

  console.log('Fetch process:');
  console.log('1. HTTP GET request to agent description URL');
  console.log('2. Parse JSON-LD document');
  console.log('3. Validate structure and required fields');
  console.log('4. Optionally verify signature');
  console.log('5. Return parsed agent description');
  console.log('');

  // Step 7: Discovery best practices
  console.log('Step 7: Discovery Best Practices...');
  console.log('');
  console.log('Active Discovery:');
  console.log('  ✓ Use for discovering agents in known domains');
  console.log('  ✓ Implement caching to reduce network requests');
  console.log('  ✓ Handle pagination for large agent lists');
  console.log('  ✓ Verify agent descriptions after fetching');
  console.log('');
  console.log('Passive Discovery:');
  console.log('  ✓ Register with multiple search services');
  console.log('  ✓ Keep agent description up to date');
  console.log('  ✓ Use specific keywords and capabilities');
  console.log('  ✓ Implement search result ranking');
  console.log('');
  console.log('Security:');
  console.log('  ✓ Verify DID signatures on agent descriptions');
  console.log('  ✓ Validate agent capabilities before interaction');
  console.log('  ✓ Use HTTPS for all discovery requests');
  console.log('  ✓ Implement rate limiting for discovery requests');
  console.log('');

  console.log('=== Example Complete ===');
  console.log('\nKey Takeaways:');
  console.log('- Active discovery: fetch from known domains');
  console.log('- Passive discovery: register with search services');
  console.log('- Always verify agent descriptions');
  console.log('- Implement caching for performance');
}

// Run the example
main().catch(console.error);
