# Contributing to KeyWrit

## Prerequisites

- [Bun](https://bun.sh/) (latest version)

## Setup

```bash
git clone https://github.com/keywrit/keywrit.git
cd keywrit
bun install
```

## Development Commands

```bash
bun test           # Run tests
bun run typecheck  # Type check with TypeScript
bun run build      # Build with bunup
bun run dev        # Build in watch mode
bun run coverage   # Run tests with coverage
```

## Project Structure

```
src/
├── index.ts           # Main exports and one-shot validation
├── constants.ts       # Version and issuer constants
├── errors.ts          # Error definitions
├── crypto/
│   └── ed25519.ts     # Ed25519 signature verification
├── jwt/
│   ├── decode.ts      # JWT decoding
│   └── verify.ts      # JWT verification
├── types/
│   ├── config.ts      # Configuration types
│   ├── jwt.ts         # JWT structure types
│   ├── results.ts     # Validation result types
│   └── ...            # Other type definitions
├── utils/
│   ├── base64url.ts   # Base64URL encoding
│   ├── domain.ts      # Domain matching
│   ├── keys.ts        # Public key parsing
│   └── time.ts        # Time/expiration utilities
└── validators/
    ├── base.ts        # Base validator class
    ├── bound.ts       # Token-bound validator
    ├── unbound.ts     # On-demand validator
    └── claims/        # Claim validation logic
```

## Code Style

- TypeScript with strict mode
- Follow existing patterns in the codebase
- Export types explicitly from `types/index.ts`
- Keep modules focused and single-purpose

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `bun test` and `bun run typecheck`
5. Submit a pull request with a clear description
