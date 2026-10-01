# ADR-0003: Name Images With Red Hat's Vocabulary, One Package per Image

| Field            | Value                                                                                |
| ---------------- | ------------------------------------------------------------------------------------ |
| ID               | ADR-0003                                                                             |
| Scope            | Repo                                                                                 |
| Status           | Accepted                                                                             |
| Decision-subject | What the published images are called and which images make up the family.            |
| Date accepted    | 2026-10-01                                                                           |
| Date             | 2026-10-01                                                                           |
| Last reviewed    | 2026-10-01                                                                           |
| Authors          | Nick Warila (@NWarila)                                                               |
| Decision-makers  | Nick Warila (sole portfolio maintainer)                                              |
| Consulted        | Red Hat's Universal Base Image 9 package repositories and image catalog naming.      |
| Informed         | Consumers of the images published from this repository.                              |
| Reversibility    | Low                                                                                  |
| Review-by        | 2027-04-01                                                                           |

## TL;DR

Each image is published as its own package, `ghcr.io/nwarila/ubi9-<name>`. The names use the words
Red Hat uses for its own Universal Base Image 9 images, so that anyone familiar with that catalog
recognizes what each image is. This record also lists the family.

## Context and Problem Statement

Image names are the hardest part of a family to change: consumers pin them, and signatures are
verified against them. The three images published by the previous pipeline were named
`ubi9-base-micro`, `ubi9-base-python`, and `ubi9-base-java`. The prefix `base-` carries no
information, and `base-java` cannot say which Java it holds once more than one is published.

## Decision Drivers

1. **Recognition.** A reader who knows Universal Base Image 9 should know what an image is from its
   name alone.
2. **The version belongs in the name.** Each runtime line is a different image with its own life.
3. **Tags are for releases.** A tag should identify a build of an image, not which image it is.
4. **Runtime and builder must not be confused.** An image that carries a compiler and a shell must be
   distinguishable at a glance from one that does not.

## Considered Options

1. Short names with the version last, and a `-builder` suffix for toolchain images.
2. The vocabulary Red Hat uses for Universal Base Image 9.
3. One package per language, with the version in the tag.

## Decision Outcome

Chosen option: **Option 2, the vocabulary Red Hat uses for Universal Base Image 9.**

Each image is one package named `ghcr.io/nwarila/ubi9-<name>`. The family is:

| Folder | Package | Contents |
| --- | --- | --- |
| `images/micro/` | `ubi9-micro` | Minimal base for static and dynamically linked binaries. |
| `images/openjdk-17-runtime/` | `ubi9-openjdk-17-runtime` | OpenJDK 17 headless runtime. |
| `images/openjdk-21-runtime/` | `ubi9-openjdk-21-runtime` | OpenJDK 21 headless runtime. |
| `images/openjdk-25-runtime/` | `ubi9-openjdk-25-runtime` | OpenJDK 25 headless runtime. |
| `images/python-312/` | `ubi9-python-312` | Python 3.12 runtime. |
| `images/nodejs-22/` | `ubi9-nodejs-22` | Node.js 22 runtime. |
| `images/nodejs-24/` | `ubi9-nodejs-24` | Node.js 24 runtime. |
| `images/go-toolset/` | `ubi9-go-toolset` | Go toolchain, a builder image. |

None of these is built or published yet. Programs compiled from Go or Rust need no runtime image and
run on `ubi9-micro`.

The three packages published by the previous pipeline keep their names and are not renamed. The
names above are new packages.

## Pros and Cons of the Options

### Option 1: Short names, version last

- Good, because the names are the shortest and the suffix makes a builder unmistakable.
- Bad, because the names are this project's own and must be learned.

### Option 2: Red Hat's vocabulary

- Good, because the names are already familiar to users of Universal Base Image 9.
- Good, because `-runtime` and `-toolset` already separate a runtime from a toolchain.
- Bad, because the names are longer.
- Bad, because they resemble Red Hat's own image names, so documentation must state plainly that
  these images are built by this project and are not Red Hat's.

### Option 3: Version in the tag

- Good, because there are fewer packages.
- Bad, because a tag would then select a different image line, which makes pinning by digest and
  reading signatures harder, and one folder would no longer correspond to one package.

## Confirmation

- Every package published from this repository is named `ubi9-<name>` for a folder `images/<name>/`.
- On 2026-10-01 the Universal Base Image 9 package repositories for both `x86_64` and `aarch64` offered
  `java-17-openjdk-headless`, `java-21-openjdk-headless`, `java-25-openjdk-headless`, `python3.12`,
  `go-toolset`, and Node.js at major versions 22 and 24.

## Consequences

### Positive

- Each runtime line is published, pinned, and retired independently.

### Negative

- Adding or retiring a runtime line means adding or retiring a package, and revising this record.

### Neutral

- Universal Base Image 9 offers OpenJDK 8 and 11 and Node.js 16, 18, and 20, which this family does
  not include. It offers no OpenJDK 18 or 22.

## Assumptions

- Red Hat continues to ship these runtime lines for Universal Base Image 9 for as long as the
  corresponding image is published here.
