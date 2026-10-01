# ADR-0002: Structure the Repository as an Image Monorepo

| Field            | Value                                                                                |
| ---------------- | ------------------------------------------------------------------------------------ |
| ID               | ADR-0002                                                                             |
| Scope            | Repo                                                                                 |
| Status           | Accepted                                                                             |
| Decision-subject | How the repository is organized, what it is called, and what belongs in it.          |
| Date accepted    | 2026-10-01                                                                           |
| Date             | 2026-10-01                                                                           |
| Last reviewed    | 2026-10-01                                                                           |
| Authors          | Nick Warila (@NWarila)                                                               |
| Decision-makers  | Nick Warila (sole portfolio maintainer)                                              |
| Consulted        | The layouts of the distroless, Chainguard images, and Docker official-images projects. |
| Informed         | Consumers of the images published from this repository.                              |
| Reversibility    | Medium                                                                               |
| Review-by        | 2027-04-01                                                                           |

## TL;DR

One repository holds the whole image family. Each image has one folder under `images/`, named exactly
like the package it publishes. The repository holds base, runtime, and builder images only;
applications live elsewhere and consume these images by digest.

## Context and Problem Statement

ADR-0001 removed the previous pipeline and left an empty tree. Before any image is rebuilt, the
repository needs a shape that a maintainer who did not build it can read in one pass, and that does
not have to change when an image is added.

The repository was created to publish a single image and was named for it. It now holds a family.

## Decision Drivers

1. **One rule from folder to package.** A reader should be able to find the source of any published
   image without a lookup table.
2. **Adding an image adds a folder.** No shared file should need restructuring when the family grows.
3. **A stable boundary.** What does not belong in the repository should be as clear as what does.
4. **Low upkeep.** One pipeline and one set of repository settings, not one per image.

## Considered Options

1. One repository per image.
2. One repository for the image family, one folder per image.
3. One repository for the image family and the applications built on it.

## Decision Outcome

Chosen option: **Option 2, one repository for the image family, one folder per image.**

- The repository takes the name `ubi9-images`.
- Each image lives in `images/<name>/`, where `<name>` is the published package name without its
  `ubi9-` prefix. The folder `images/micro/` publishes `ubi9-micro`.
- Each image folder holds that image's build file, named `Dockerfile`, and the configuration for each
  input that produces evidence about the image.
- The repository holds base images, language runtime images, and builder images that carry a
  toolchain. It does not hold applications, continuous-integration tool images, or one-off service
  images. Those live in their own repositories and consume these images by digest.

## Pros and Cons of the Options

### Option 1: One repository per image

- Good, because each image has its own signing identity and its own failure boundary.
- Bad, because every image multiplies the pipelines, rulesets, and update configuration to maintain.

### Option 2: One repository, one folder per image

- Good, because a single pipeline and a single set of settings serve every image.
- Good, because the folder name and the package name are the same word.
- Bad, because a defect in shared build steps affects every image at once.

### Option 3: Family and applications together

- Good, because everything is in one place.
- Bad, because application releases follow upstream versions while base images follow patched
  packages, and one pipeline would have to serve both rhythms.

## Confirmation

- The repository is named `ubi9-images`. At the time of writing the rename has not yet been made.
- Every folder directly under `images/` contains a `Dockerfile`, and its name with the prefix `ubi9-`
  is the name of a published package.
- No folder under `images/` builds an application.

## Consequences

### Positive

- The location of any image's source follows from its name.
- Adding an image is adding a folder.

### Negative

- All images share one signing identity, so a consumer verifies the workflow and the package, not a
  per-image repository.

### Neutral

- Until it is renamed the repository is still called `ubi9-base-micro`. GitHub redirects the old name
  after a rename.
- The directory `images/` does not exist until the first image is added.

## Assumptions

- The family stays small enough that one pipeline can build all of it.
