# KeyWrit - AI Assistant Context

See @README.md for project overview and @CONTRIBUTING.md for development setup.

## Architecture

- **validators/** - Core validation logic with bound/unbound patterns
- **types/** - TypeScript type definitions
- **jwt/** - JWT decoding and verification
- **utils/** - Helper functions (base64url, domain matching, key parsing, time)
- **crypto/** - Ed25519 signature verification using @noble/ed25519

## Testing

Uses Bun test runner. Run with `bun test`.

Test files are in `tests/` directory.

## Building

Uses [bunup](https://github.com/so1ve/bunup) for bundling. Run with `bun run build`.

Outputs ESM, CJS, and browser bundles to `dist/`.
