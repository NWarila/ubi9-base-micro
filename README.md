# ubi9-images

Container base images built on Red Hat Universal Base Image 9: a minimal base, language runtimes, and
toolchain images, each published as its own package.

## Status: being rebuilt from zero

On 2026-10-01 the previous build pipeline was removed from `main`. It is preserved unchanged at the
`legacy-final` tag and on the `legacy` branch, including its workflows, tooling, lockfiles, and
documentation. The reasons are recorded in
[ADR-0001](docs/decision-records/repo/0001-rebuild-the-image-family-from-zero.md).

Nothing is built or published from `main` yet. There is no workflow in this repository.

## Images published by the previous pipeline

These remain pullable and verifiable at the digests below. They receive **no further updates**; treat
them as unmaintained for vulnerability purposes until the rebuilt pipeline publishes replacements.

| Image | Last published digest |
| --- | --- |
| `ghcr.io/nwarila/ubi9-base-micro` | `sha256:8af7c28c6280a09d057fa649483ccd33c6fd25dce7863147bfb4dc68f3702eca` |
| `ghcr.io/nwarila/ubi9-base-python` | `sha256:29f17238f22163444b7bd0e7e6d4897de9f09f1ab1f39af78088c6e08d7c3cf1` |
| `ghcr.io/nwarila/ubi9-base-java` | `sha256:89db8a7428874c1204a4beaa8145f36ece7365b361fb4669ff9eb6e77a65a37d` |

Instructions for verifying those images are in the documentation at the `legacy-final` tag.

## Documentation

- [Decision records](docs/decision-records/) — organization baseline under `org/`, this repository's
  under `repo/`.
- [Security policy](SECURITY.md), [contributing](CONTRIBUTING.md), [support](SUPPORT.md).

## License

[MIT](LICENSE).
