# Examples

Human-readable output:

```bash
headerlens https://app.example.test
```

Versioned machine output for an evidence pipeline:

```bash
headerlens -json https://app.example.test > result.json
```

Disable redirect following completely:

```bash
headerlens -max-redirects 0 https://app.example.test
```

Only after confirming authorization for the destination hostname:

```bash
headerlens -allow-cross-host-redirects https://app.example.test
```

Raw Set-Cookie values are sensitive and are excluded by default. Enable them only when the engagement requires raw cookie evidence:

```bash
headerlens -json -include-sensitive-headers https://app.example.test > sensitive-result.json
```
