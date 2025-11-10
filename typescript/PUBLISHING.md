# Publishing Checklist

This document outlines the steps to publish a new version of the ANP TypeScript SDK to npm.

## Pre-Release Checklist

### 1. Code Quality
- [ ] All tests pass: `npm test`
- [ ] Linting passes: `npm run lint`
- [ ] Type checking passes: `npm run typecheck`
- [ ] Code coverage is at least 80%: `npm run test:coverage`
- [ ] All examples work correctly

### 2. Documentation
- [ ] README.md is up to date
- [ ] CHANGELOG.md is updated with new changes
- [ ] API documentation is current
- [ ] All examples are tested and documented
- [ ] Migration guide is provided (for breaking changes)

### 3. Version Management
- [ ] Version number follows semantic versioning
- [ ] Version is updated in `package.json`
- [ ] Version is updated in `CHANGELOG.md`
- [ ] Git tag is created for the version

### 4. Build Verification
- [ ] Clean build succeeds: `npm run clean && npm run build`
- [ ] Package contents are correct: `npm pack --dry-run`
- [ ] Both ESM and CommonJS outputs are generated
- [ ] Type definitions are generated correctly
- [ ] Source maps are included

### 5. Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Examples can be run successfully
- [ ] Package can be installed locally: `npm pack && npm install <tarball>`

## Publishing Steps

### 1. Prepare the Release

```bash
# Ensure you're on the main branch
git checkout main
git pull origin main

# Update version (choose one)
npm version patch  # for bug fixes (0.1.0 -> 0.1.1)
npm version minor  # for new features (0.1.0 -> 0.2.0)
npm version major  # for breaking changes (0.1.0 -> 1.0.0)

# Update CHANGELOG.md with the new version and date
# Edit CHANGELOG.md manually
```

### 2. Test the Package

```bash
# Run all tests
npm test

# Run linting
npm run lint

# Type check
npm run typecheck

# Test the build
npm run build

# Verify package contents
npm pack --dry-run
```

### 3. Commit and Tag

```bash
# Commit the version bump
git add package.json CHANGELOG.md
git commit -m "chore: release v0.x.x"

# Create a git tag
git tag -a v0.x.x -m "Release v0.x.x"

# Push to remote
git push origin main
git push origin v0.x.x
```

### 4. Publish to npm

```bash
# Dry run to verify everything
npm publish --dry-run

# Publish to npm (requires npm login)
npm publish --access public

# For scoped packages, ensure public access
```

### 5. Post-Release

```bash
# Create GitHub release
# Go to https://github.com/chgaowei/AgentNetworkProtocol/releases/new
# - Select the tag you just created
# - Add release title: "ANP TypeScript SDK v0.x.x"
# - Copy content from RELEASE_NOTES.md
# - Attach the tarball from npm pack

# Announce the release
# - Update project README if needed
# - Post to relevant communities
# - Update documentation site
```

## Troubleshooting

### Build Fails
- Check TypeScript errors: `npm run typecheck`
- Verify all dependencies are installed: `npm install`
- Clear dist folder: `npm run clean`

### Tests Fail
- Run tests in watch mode: `npm run test:watch`
- Check for environment-specific issues
- Verify all test fixtures are up to date

### Publish Fails
- Ensure you're logged in: `npm whoami`
- Check npm registry: `npm config get registry`
- Verify package name is available: `npm view @anp/typescript-sdk`
- Check for 2FA requirements

### Version Conflicts
- Ensure version in package.json matches git tag
- Check if version already exists on npm: `npm view @anp/typescript-sdk versions`

## Rollback Procedure

If you need to unpublish or deprecate a version:

```bash
# Deprecate a version (preferred over unpublish)
npm deprecate @anp/typescript-sdk@0.x.x "Reason for deprecation"

# Unpublish (only within 72 hours of publish)
npm unpublish @anp/typescript-sdk@0.x.x

# Note: Unpublishing is discouraged and may not be possible for popular packages
```

## Automated Publishing (Future)

Consider setting up automated publishing with GitHub Actions:

```yaml
# .github/workflows/publish.yml
name: Publish to npm

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm test
      - run: npm run build
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

## Security Considerations

- Never commit npm tokens or credentials
- Use 2FA for npm account
- Review package contents before publishing
- Scan for vulnerabilities: `npm audit`
- Keep dependencies up to date

## Support

For questions or issues with publishing:
- Check npm documentation: https://docs.npmjs.com/
- Contact package maintainers
- Open an issue on GitHub
