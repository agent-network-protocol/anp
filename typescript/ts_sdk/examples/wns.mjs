import {
  buildResolutionUrl,
  createHandleServiceEntry,
  parseUri,
  validateHandle,
  wns,
} from '../dist/index.js';

const [localPart, domain] = validateHandle('Alice.Example.COM');
console.log('Normalized handle:', `${localPart}.${domain}`);
console.log('Resolution URL:', buildResolutionUrl(localPart, domain));
console.log('WBA URI:', wns.buildUri(localPart, domain));
console.log('Parsed URI:', parseUri('wba://alice.example.com'));
console.log(
  'ANPHandleService entry:',
  createHandleServiceEntry('did:wba:example.com:user:alice', localPart, domain)
);
