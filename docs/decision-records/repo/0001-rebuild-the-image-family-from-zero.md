# ADR-0001: Rebuild the Image Family From Zero

| Field            | Value                                                                              |
| ---------------- | ---------------------------------------------------------------------------------- |
| ID               | ADR-0001                                                                           |
| Scope            | Repo                                                                               |
| Status           | Accepted                                                                           |
| Decision-subject | Whether to keep reducing the existing build pipeline or to remove it and rebuild.  |
| Date accepted    | 2026-10-01                                                                         |
| Date             | 2026-10-01                                                                         |
| Last reviewed    | 2026-10-01                                                                         |
| Authors          | Nick Warila (@NWarila)                                                             |
| Decision-makers  | Nick Warila (sole portfolio maintainer)                                            |
| Consulted        | The repository's own history and an independent review of a reduction plan.        |
| Informed         | Consumers of the images published from this repository.                            |
| Reversibility    | High                                                                               |
| Review-by        | 2027-04-01                                                                         |

## TL;DR

The build pipeline that published three images from this repository is removed from `main` and
preserved at the `legacy-final` tag. The image family is rebuilt from an empty tree: each image is
first built by hand, and only steps that have been performed by hand are then written down as
automation.

## Context and Problem Statement

At the `legacy-final` tag this repository holds 28,974 lines under `tools/` and 5,013 lines of
workflow in 12 files, in order to publish three images. A single file, `tools/verify.py`, is 12,152
lines. Absorbing one patched RPM into one image required a change of ten replaced lines across three
files, and that change took a multi-hour cycle of specification, implementation, and review.

The operating target for this repository is that an engineer who did not build it can keep it healthy
in about ten minutes a week. The existing pipeline cannot meet that target, and reducing it in place
means proving, for every removed part, that nothing depended on it.

A plan to replace the pipeline by specification alone was reviewed before any work started. The
review found seven high-severity defects, and their common cause was that the plan described
mechanisms nobody had yet run.

## Decision Drivers

1. **Operability.** The repository must be understandable and maintainable by someone other than its
   author.
2. **Honest claims.** Documentation must describe what exists. Several documents at `legacy-final`
   describe gates that had already been removed.
3. **Evidence before automation.** A step is automated only after it has been carried out by hand and
   its real output has been seen.
4. **Recoverability.** Nothing is lost: the prior tree stays reachable and the published images stay
   pullable.

## Considered Options

1. Keep reducing the existing pipeline in place.
2. Build a replacement beside the existing pipeline, then cut over.
3. Remove the existing pipeline from `main` and rebuild from an empty tree.

## Decision Outcome

Chosen option: **Option 3, remove the existing pipeline from `main` and rebuild from an empty tree.**

`main` keeps only the organization baseline files and this record. The prior tree is preserved at the
signed tag `legacy-final` and on the branch `legacy`. Decision records 0001 through 0016 of the
previous pipeline are not carried forward; they remain readable at the tag, and decision numbering
for this repository restarts with this record.

The rebuild proceeds in this order: build every image by hand from a hand-curated package list; then
write down the first step those builds have in common; then add scanning, reporting, publishing, and
updating one step at a time, each one performed by hand before it is automated.

## Pros and Cons of the Options

### Option 1: Reduce in place

- Good, because published images keep receiving updates throughout.
- Bad, because each removal needs proof that the remaining parts still deliver what the removed part
  delivered, which is the cost this decision is meant to end.

### Option 2: Build beside, then cut over

- Good, because consumers see no gap.
- Bad, because the existing publishers run on every push to `main` and would have to be isolated
  first, and because two pipelines exist at once during the work.

### Option 3: Remove and rebuild

- Good, because every file on `main` afterwards exists by a deliberate decision.
- Good, because the work is reversible by returning to the tag.
- Bad, because images already published receive no updates until the rebuilt pipeline publishes.

## Confirmation

- `git ls-files` on `main` lists only the organization baseline files, this record, and repository
  configuration.
- The tag `legacy-final` resolves to commit `4347244c59f77c982f498a2e0baee730014b17af` and carries a
  verified signature.
- The three images listed in `README.md` resolve to the digests recorded there.

## Consequences

### Positive

- The repository's purpose and contents can be stated in one sentence.
- Documentation and behavior cannot disagree, because the documentation that described removed
  behavior is gone.

### Negative

- Until the rebuilt pipeline publishes, the three previously published images are unmaintained for
  vulnerability purposes.
- The repository has no continuous integration until the first workflow is deliberately added.

### Neutral

- Required status checks configured for the previous pipeline no longer report and must be updated by
  the repository owner.

## Assumptions

- Consumers pin these images by digest, so removing the pipeline does not change what they run.
