# Releasing PySOAR

This page describes what `.github/workflows/release.yml` does and the steps to
cut a release. If you change the workflow, update this page in the same change.

Status: the workflow has not run yet, and no `v*` tag has been cut. The local
checks are listed at the end of this page.

## Where the version comes from

- `VERSION` at the repository root holds the release version as a semantic
  version (`MAJOR.MINOR.PATCH`, with an optional `-pre.release` suffix). It
  started at `0.9.0`.
- `src/core/version.py` reads that file into `__version__`. `src.__version__`
  re-exports it, and it is the version the OpenAPI document, `GET /` and
  `GET /api/v1/health/detailed` report. A missing or malformed `VERSION` file
  stops the import with an error. The module never falls back to a default
  version.
- The build commit comes from the `PYSOAR_COMMIT` build argument. The backend
  Dockerfile turns it into an environment variable of the same name. If it is
  not set, or is not a hexadecimal git object name, the commit is reported as
  `unknown`.
- `GET /api/v1/health` (unauthenticated) returns both:

  ```json
  {"status": "healthy", "version": "0.9.0", "commit": "<40-character sha>"}
  ```

`pyproject.toml` and `frontend/package.json` have their own `version` fields
(`1.0.0` and `0.0.0`). Neither the release workflow nor the application reads
them, so they do not identify a release.

## Cutting a release

1. Pick a commit on `main` where the CI/CD Pipeline (`ci.yml`) passed on the
   push to `main`. The release workflow checks both conditions and stops if
   either one fails.
2. Bump `VERSION`, for example to `0.9.1`. Optionally, add a
   `## [0.9.1] - YYYY-MM-DD` section to `CHANGELOG.md` (see below). Commit the
   change, push it to `main`, and wait for CI to pass on that commit.
3. Tag that commit with `v` plus the exact contents of `VERSION`, then push
   the tag:

   ```sh
   git checkout main && git pull
   git tag -a "v$(cat VERSION)" -m "PySOAR $(cat VERSION)"
   git push origin "v$(cat VERSION)"
   ```

4. Watch the Release workflow in the repository's Actions tab.

## What the workflow does

Pushing a tag that starts with `v` runs three jobs in order. A failure in one
job stops the jobs after it.

1. **verify** (`contents: read`, `actions: read`)
   - The tag must equal `v` + `VERSION`, and `VERSION` must be a semantic
     version. `v0.9.0` with `VERSION` = `0.9.0` passes. `v0.9`, `0.9.0`, or a
     tag that differs from `VERSION` fails.
   - The tagged commit must be an ancestor of `origin/main`.
   - The commit must have at least one successful `ci.yml` run triggered by
     `push`. A run that is still in progress does not count. If you tagged too
     early, wait for CI, delete the tag, and push it again:
     `git push --delete origin vX.Y.Z`, then repeat step 3.
2. **images** (`contents: read`, `packages: write`), one run per image:

   | Image | Build | Dockerfile |
   |---|---|---|
   | `ghcr.io/<owner>/pysoar-backend` | context `.`, target `production` | `Dockerfile` |
   | `ghcr.io/<owner>/pysoar-frontend` | context `./frontend` | `frontend/Dockerfile` |

   `<owner>` is the repository owner in lowercase, currently
   `jacobpeart-cyber`. Each image is pushed with these tags:
   - `<version>`, for example `0.9.0`
   - `<major>.<minor>`, for example `0.9`, which moves to the newest patch. It
     is not pushed for a pre-release version such as `1.0.0-rc.1`.
   - `sha-<short commit>`, for example `sha-dc336f6`

   Neither image gets a `latest` tag.

   OCI labels on both images:
   - `org.opencontainers.image.source`, `revision` (the tagged commit) and
     `created`, set by `docker/metadata-action`
   - `org.opencontainers.image.version` = `VERSION`
   - `org.opencontainers.image.title` = the image name

   The build arguments `PYSOAR_COMMIT` (the tagged commit), `PYSOAR_VERSION`
   and `PYSOAR_BUILD_DATE` are passed too. In the backend image,
   `PYSOAR_COMMIT` is what `/api/v1/health` reports.

   After each push, `anchore/sbom-action` generates an SPDX JSON SBOM of the
   pushed image by digest, named `pysoar-backend-<version>.spdx.json` or
   `pysoar-frontend-<version>.spdx.json`.
3. **release** (`contents: write`) runs `gh release create` with:
   - title `PySOAR <version>`
   - the pre-release flag when the version has a pre-release suffix
   - both SBOMs attached as release assets
   - release notes containing:
     - the `## [<version>]` section of `CHANGELOG.md`, when the file exists
       and has that section
     - the `docker pull` commands and the pushed digest of each image
     - the commit list (`git log --no-merges`) since the previous `v*` tag.
       The first release has no previous tag, and its notes say so instead
       of listing commits.

Every third-party action in `release.yml` is pinned to a full commit SHA, with
the release it was resolved from in a comment.

### When a run fails partway

- If **verify** fails, nothing has been pushed. Fix the cause, delete the tag
  and push it again.
- If **images** or **release** fails after a push, some tags may already
  exist in GHCR. If the cause was transient, use "Re-run failed jobs" on the
  same run, which rebuilds from the same commit and overwrites the same tags.
  Do not reuse a version number for different code. Bump `VERSION` and cut a
  new tag instead.
- If a GitHub release for the tag already exists, `gh release create` fails.
  Delete the release first if you mean to recreate it.

## Pulling the images

```sh
docker pull ghcr.io/jacobpeart-cyber/pysoar-backend:0.9.0
docker pull ghcr.io/jacobpeart-cyber/pysoar-frontend:0.9.0
```

GitHub's documented default visibility for a newly published container
package is private. To pull a private package, run
`docker login ghcr.io -u <github user>` with a personal access token that has
`read:packages`. To allow anonymous pulls, change the package's visibility in
its settings on GitHub.

Check what you pulled:

```sh
docker inspect --format '{{json .Config.Labels}}' ghcr.io/jacobpeart-cyber/pysoar-backend:0.9.0
docker run --rm ghcr.io/jacobpeart-cyber/pysoar-backend:0.9.0 \
  python -c "from src.core.version import __version__, get_commit; print(__version__, get_commit())"
```

## Docker Compose and image tags

`docker-compose.yml` names the images it builds:

- `api`, `worker`, `scheduler` and `flower` use
  `ghcr.io/jacobpeart-cyber/pysoar-backend:${PYSOAR_IMAGE_TAG:-local}`.
- `frontend` uses `ghcr.io/jacobpeart-cyber/pysoar-frontend:${PYSOAR_IMAGE_TAG:-local}`.

The `build:` sections are still there:

- **Default (`PYSOAR_IMAGE_TAG` unset):** `docker compose build` (or
  `up --build`) builds locally and tags the images `:local`. Nothing is
  pushed. To have `/api/v1/health` report the commit, pass it in:
  `PYSOAR_COMMIT=$(git rev-parse HEAD) docker compose build`. Without it, the
  commit is `unknown`.
- **A released version (`PYSOAR_IMAGE_TAG=0.9.0`):**
  `docker compose pull api worker scheduler flower frontend` fetches that
  release.

  The compose file bind-mounts host paths over parts of the image:
  - `./src` and `./alembic` over the backend code
  - `./frontend/dist` over the frontend bundle

  So the running code is whatever the host checkout holds. Check out the same
  tag (`git checkout v0.9.0`) before you start a pulled release, and keep a
  built `./frontend/dist` on the host. If that directory is missing, Docker
  creates it empty and nginx serves no UI.

  The `VERSION` file is not bind-mounted. `/api/v1/health` reports the version
  baked into the image.

The upgrade procedure, including `alembic upgrade head`, is the same as for a
local build.

## CHANGELOG.md convention

`CHANGELOG.md` does not exist yet. When it is added, use the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) layout so the
workflow can find each release's section:

```markdown
# Changelog

## [Unreleased]

## [0.9.1] - 2026-11-02
### Added
- ...
### Fixed
- ...
```

The workflow copies the lines between `## [<version>]` and the next `## [`
heading into the release notes. The match is on the heading prefix, so the
date suffix is optional. If the section is missing, the release still goes
ahead without it, and the notes carry only the commit list.

## What CI checks on every push

The "Build Docker Images" job in `ci.yml` builds both images with the same
Dockerfiles, targets and cache scopes as the release, and pushes nothing. It
then checks four things:

- the backend image imports the app
- the backend image reports `VERSION` and the build commit
- the frontend image starts nginx and serves the built `index.html`
- `api` is mapped to loopback for that frontend check, because
  `frontend/nginx.conf` proxies `/api` to `http://api:8000` and nginx refuses
  to start when that name does not resolve

## Validated locally, and what was not

Validated locally, before the first tag:

- `actionlint` 1.7.7 on `release.yml` and `ci.yml`. shellcheck was not
  installed, so the embedded shell was not linted by it.
- A YAML parse of both workflows and `docker-compose.yml`, plus
  `docker compose config`.
- The semver check and the `CHANGELOG.md` section extraction, run in bash
  against sample input.
- A local `docker build` of both images, with each image's labels,
  `/api/v1/health` output and nginx response checked.

Not validated: the workflow run itself. That covers the GHCR push, SBOM
generation, release creation, the CI-status lookup and the `<major>.<minor>`
tag behaviour. They are exercised for the first time when the first `v*` tag
is pushed.
