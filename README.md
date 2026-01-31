# KeyWrit

A TypeScript library for validating software licenses using public key signatures. Designed for client-side license
validation with JWT-based tokens.

## Installation

```bash
npm install keywrit
# or
bun add keywrit
```

## Quick Start

### Issuing Tokens

Generate license tokens at **[keywrit.github.io/hub](https://keywrit.github.io/hub/)**.

### Functional API

For one-shot validation:

```typescript
import { validateLicense } from "keywrit";

const result = await validateLicense("my-app", token, {
  publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
});

if (result.valid) {
  console.log("License valid for:", result.license.sub);
  console.log("License kind:", result.license.kind);
  console.log("Flags:", result.license.flags);
} else {
  console.error("Invalid license:", result.error.message);
}
```

### Class-based API

For reusable validation with helper methods:

```typescript
import { LicenseValidator } from "keywrit";

const validator = await LicenseValidator.create("my-app", {
  publicKeyUrl: "https://raw.githubusercontent.com/my-org/my-app/main/license.pub",
});

// Full validation
const result = await validator.validate(token);

// Check license kind
if (await validator.hasKind(token, "pro")) {
  console.log("Pro license detected");
}

// Check feature flags
const flagResult = await validator.hasFlag(token, "export");
if (flagResult.enabled) {
  console.log("Export feature enabled");
}

// Access custom features
const maxUsers = await validator.getFeature<number>(token, "maxUsers");
```

### Token-bound Validation

Bind a validator to a specific token for sync access:

```typescript
const bound = await validator.bind(token);

if (bound.valid) {
  // Sync access to license data
  console.log(bound.payload.sub);
  console.log(bound.hasFlag("export"));
  console.log(bound.getFeature<number>("maxUsers"));
}
```

## Documentation

For full documentation, API reference, and more examples, visit
**[keywrit.github.io/docs](https://keywrit.github.io/docs/)**.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](./LICENSE)
