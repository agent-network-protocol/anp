/**
 * Agent Discovery Example
 * 
 * Demonstrates complete agent discovery with mock services:
 * - Creating multiple agents
 * - Active discovery from a domain
 * - Passive discovery via search service
 */

import { ANPClient } from '../../dist/index.js';
// @ts-ignore - Node.js built-in module
import { createServer } from 'http';

// Mock discovery service
let registeredAgents: any[] = [];

function startMockServices() {
  // Discovery server at localhost:9100
  const discoveryServer = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.url === '/.well-known/agent-descriptions') {
      // Return agent descriptions
      const discoveryDoc = {
        '@context': { ad: 'https://agent-network-protocol.org/ns/ad#' },
        '@type': 'CollectionPage',
        url: 'http://localhost:9100/.well-known/agent-descriptions',
        items: registeredAgents.map(agent => ({
          '@type': 'ad:AgentDescription',
          name: agent.name,
          '@id': agent.url,
        })),
      };
      res.writeHead(200);
      res.end(JSON.stringify(discoveryDoc));
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  });

  // Search service at localhost:9101
  const searchServer = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.method === 'POST' && (req.url === '/' || req.url === '/register')) {
      // Register agent
      let body = '';
      req.on('data', chunk => (body += chunk));
      req.on('end', () => {
        try {
          const data = JSON.parse(body);
          // Extract agent description URL from request
          const agentUrl = data.agentDescriptionUrl || data.url;
          if (agentUrl) {
            registeredAgents.push({
              name: `Agent from ${agentUrl}`,
              url: agentUrl,
            });
          }
          res.writeHead(200);
          res.end(JSON.stringify({ success: true, registered: agentUrl }));
        } catch (e) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Invalid request' }));
        }
      });
    } else if (req.method === 'POST' && req.url === '/search') {
      // Search agents
      let body = '';
      req.on('data', chunk => (body += chunk));
      req.on('end', () => {
        try {
          const query = JSON.parse(body);
          // Filter agents based on keywords
          let results = registeredAgents;
          if (query.keywords && Array.isArray(query.keywords)) {
            results = registeredAgents.filter(agent =>
              query.keywords.some((keyword: string) =>
                agent.name.toLowerCase().includes(keyword.toLowerCase())
              )
            );
          }
          // Return results in SearchResult format with items array
          res.writeHead(200);
          res.end(JSON.stringify({
            items: results,
            total: results.length,
            hasMore: false,
          }));
        } catch (e) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Invalid query' }));
        }
      });
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  });

  discoveryServer.listen(9100);
  searchServer.listen(9101);

  return { discoveryServer, searchServer };
}

async function main() {
  console.log('=== Agent Discovery Example ===\n');

  // Start mock services
  console.log('Starting mock services...');
  const { discoveryServer, searchServer } = startMockServices();
  console.log('✓ Discovery service: http://localhost:9100');
  console.log('✓ Search service: http://localhost:9101');
  console.log();

  const client = new ANPClient();

  // Create multiple agents
  console.log('Creating agents...');
  const agents: Array<{ identity: any; description: any }> = [];

  for (let i = 1; i <= 3; i++) {
    const identity = await client.did.create({
      domain: `localhost:${9000 + i}`,
      path: `agent-${i}`,
    });

    let description = client.agent.createDescription({
      name: `Agent ${i}`,
      description: `Test agent number ${i}`,
      protocolVersion: '0.1.0',
      did: identity.did,
    });

    description = client.agent.addInterface(description, {
      type: 'Interface',
      protocol: 'HTTP',
      version: '1.1',
      url: `http://localhost:${9000 + i}/api`,
    });

    const signedDescription = await client.agent.signDescription(
      description,
      identity,
      `challenge-${i}`,
      `localhost:${9000 + i}`
    );

    agents.push({ identity, description: signedDescription });
    
    // Register with mock service
    registeredAgents.push({
      name: signedDescription.name,
      url: `http://localhost:${9000 + i}/description.json`,
      description: signedDescription.description,
    });

    console.log(`✓ Created ${signedDescription.name}: ${identity.did}`);
  }
  console.log();

  // Wait a bit for servers to be ready
  await new Promise(resolve => setTimeout(resolve, 100));

  // Active Discovery
  console.log('Active Discovery:');
  console.log('Discovering agents from localhost:9100...');
  try {
    const discovered = await client.discovery.discoverAgents('localhost:9100');
    console.log(`✓ Found ${discovered.length} agents:`);
    discovered.forEach((agent, i) => {
      console.log(`  ${i + 1}. ${agent.name} - ${agent['@id']}`);
    });
  } catch (error: any) {
    console.log('✗ Discovery failed:', error.message);
  }
  console.log();

  // Passive Discovery - Register
  console.log('Passive Discovery - Registration:');
  try {
    await client.discovery.registerWithSearchService(
      'http://localhost:9101',
      'http://localhost:9004/description.json',
      agents[0].identity
    );
    console.log('✓ Registered with search service');
  } catch (error: any) {
    console.log('✗ Registration failed:', error.message);
  }
  console.log();

  // Search
  console.log('Searching for agents:');
  try {
    const results = await client.discovery.searchAgents(
      'http://localhost:9101/search',
      { keywords: ['Agent'] }
    );
    console.log(`✓ Found ${results.length} matching agents:`);
    results.forEach((agent: any, i: number) => {
      console.log(`  ${i + 1}. ${agent.name} - ${agent['@id'] || agent.url}`);
    });
  } catch (error: any) {
    console.log('✗ Search failed:', error.message);
  }
  console.log();

  console.log('=== Example Complete ===');

  // Cleanup
  discoveryServer.close();
  searchServer.close();
}

main().catch(console.error);
