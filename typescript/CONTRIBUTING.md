# Contributing to ANP TypeScript SDK

Thank you for your interest in contributing to the ANP TypeScript SDK! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/AgentNetworkProtocol.git
   cd AgentNetworkProtocol/ts_sdk
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Code Quality

```bash
# Run linter
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Check formatting
npm run format:check

# Type check
npm run typecheck
```

### Building

```bash
# Build the package
npm run build

# Build in watch mode
npm run dev
```

## Coding Standards

### TypeScript

- Use TypeScript for all code
- Enable strict mode
- Provide type definitions for all public APIs
- Avoid `any` types when possible

### Code Style

- Follow the Prettier configuration
- Use meaningful variable and function names
- Write self-documenting code
- Add comments for complex logic

### Testing

- Write tests before implementation (TDD)
- Aim for 80%+ code coverage
- Test both success and error cases
- Use descriptive test names

### Commits

- Use conventional commit messages:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `test:` for test changes
  - `refactor:` for code refactoring
  - `chore:` for maintenance tasks

Example:
```
feat: add DID resolution caching
fix: handle network timeout in HTTP client
docs: update API reference for authentication
```

## Pull Request Process

1. **Update Documentation**
   - Update README.md if needed
   - Add/update API documentation
   - Include examples if applicable

2. **Run All Checks**
   ```bash
   npm run typecheck
   npm run lint
   npm run test:coverage
   npm run build
   ```

3. **Create Pull Request**
   - Provide a clear description
   - Reference related issues
   - Include screenshots/examples if applicable

4. **Code Review**
   - Address review comments
   - Keep the PR focused and small
   - Rebase on main if needed

## Project Structure

```
ts_sdk/
├── src/                    # Source code
│   ├── core/              # Core modules
│   ├── protocol/          # Protocol layer
│   ├── crypto/            # Cryptography
│   ├── transport/         # Transport layer
│   ├── types/             # Type definitions
│   ├── errors/            # Error classes
│   └── index.ts           # Main entry point
├── tests/                 # Tests
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
└── examples/             # Example code
```

## Adding New Features

1. **Create an Issue**
   - Describe the feature
   - Discuss the approach
   - Get feedback from maintainers

2. **Follow TDD**
   - Write tests first
   - Implement the feature
   - Ensure all tests pass

3. **Update Documentation**
   - Add API documentation
   - Create examples
   - Update guides

### Feature Development Checklist

- [ ] Issue created and discussed
- [ ] Tests written (unit and integration)
- [ ] Implementation complete
- [ ] All tests passing
- [ ] Code coverage maintained (80%+)
- [ ] Documentation updated
- [ ] Examples added (if applicable)
- [ ] Type definitions exported
- [ ] Error handling implemented
- [ ] Changelog updated

## Testing Guidelines

### Unit Tests

- Test individual functions and classes
- Mock external dependencies
- Focus on edge cases and error conditions
- Use descriptive test names

Example:
```typescript
describe('DIDManager', () => {
  describe('createDID', () => {
    it('should create a valid DID with domain and path', async () => {
      // Test implementation
    });

    it('should throw error for invalid domain', async () => {
      // Test implementation
    });
  });
});
```

### Integration Tests

- Test complete workflows
- Use real implementations (no mocks)
- Test interactions between modules
- Verify end-to-end functionality

Example:
```typescript
describe('Authentication Flow', () => {
  it('should authenticate and make authorized request', async () => {
    // Create identities
    // Generate auth header
    // Verify signature
    // Make authenticated request
  });
});
```

### Test Coverage

- Maintain 80%+ code coverage
- Focus on critical paths
- Don't sacrifice quality for coverage
- Use coverage reports to find gaps

```bash
npm run test:coverage
```

## Code Review Guidelines

### For Contributors

- Keep PRs focused and small
- Respond to feedback promptly
- Be open to suggestions
- Test thoroughly before submitting

### For Reviewers

- Be constructive and respectful
- Focus on code quality and maintainability
- Check for security issues
- Verify tests are comprehensive
- Ensure documentation is updated

## Architecture Guidelines

### Module Organization

- Keep modules focused and cohesive
- Minimize dependencies between modules
- Use dependency injection
- Export clean public APIs

### Error Handling

- Use custom error classes
- Provide descriptive error messages
- Include error codes
- Handle errors at appropriate levels

Example:
```typescript
export class DIDResolutionError extends ANPError {
  constructor(did: string, cause?: Error) {
    super(`Failed to resolve DID: ${did}`, 'DID_RESOLUTION_ERROR');
    this.cause = cause;
  }
}
```

### Type Safety

- Use strict TypeScript settings
- Avoid `any` types
- Provide type definitions for all public APIs
- Use generics where appropriate

### Performance

- Implement caching where beneficial
- Use connection pooling
- Avoid unnecessary computations
- Profile performance-critical code

## Documentation Standards

### Code Comments

- Document complex logic
- Explain "why" not "what"
- Keep comments up to date
- Use JSDoc for public APIs

Example:
```typescript
/**
 * Creates a new DID:WBA identity with key pairs.
 * 
 * @param options - Configuration for DID creation
 * @returns Promise resolving to DID identity
 * @throws {DIDCreationError} If key generation fails
 */
async createDID(options: CreateDIDOptions): Promise<DIDIdentity>
```

### API Documentation

- Document all public methods
- Include parameter descriptions
- Provide return type information
- Add usage examples
- Document error conditions

### Examples

- Create runnable examples
- Cover common use cases
- Include error handling
- Add explanatory comments

## Release Process

1. **Version Bump**
   - Follow semantic versioning
   - Update package.json
   - Update CHANGELOG.md

2. **Testing**
   - Run full test suite
   - Test in different environments
   - Verify examples work

3. **Documentation**
   - Update README if needed
   - Update API docs
   - Update migration guide

4. **Release**
   - Create git tag
   - Publish to npm
   - Create GitHub release
   - Announce in discussions

## Getting Help

### Resources

- [ANP Specification](https://github.com/chgaowei/AgentNetworkProtocol)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [XState Documentation](https://xstate.js.org/docs/)
- [Vitest Documentation](https://vitest.dev/)

### Communication

- **Questions**: Open a discussion
- **Bugs**: Create an issue
- **Features**: Create an issue for discussion
- **Security**: Email maintainers privately

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions
- Follow community guidelines

## Reporting Bugs

1. **Check Existing Issues**
   - Search for similar issues
   - Add to existing discussions

2. **Create a Bug Report**
   - Describe the bug
   - Provide reproduction steps
   - Include environment details
   - Add error messages/logs

## Questions?

- Open a [Discussion](https://github.com/chgaowei/AgentNetworkProtocol/discussions)
- Join our community channels
- Contact the maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
