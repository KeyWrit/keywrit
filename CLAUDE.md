# KeyWrit - AI Assistant Context

See @README.md for project overview and @CONTRIBUTING.md for development setup.

## Package Manager

Use `bun` to run any command.

## After Commits

Always run `bun run check` after making changes. This runs linting (Biome), type checking, and tests.

## Architecture

KeyWrit is signing-method agnostic. It uses PKI (public key infrastructure) for validation. The current implementation uses Ed25519, but this is an implementation detail, not a dependency.

- **validators/** - Core validation logic with bound/unbound patterns
- **types/** - TypeScript type definitions
- **jwt/** - JWT decoding and verification
- **utils/** - Helper functions (base64url, domain matching, key parsing, time)
- **crypto/** - Signature verification (currently Ed25519 via @noble/ed25519)

## Testing

Uses Vitest. Run with `bun run test` (watch mode) or `bun run test:run` (single run).

Test files are in `tests/` directory.

## Building

Uses [bunup](https://github.com/so1ve/bunup) for bundling. Run with `bun run build`.

Outputs ESM, CJS, and browser bundles to `dist/`.
