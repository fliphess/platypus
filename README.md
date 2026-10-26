# Platypus

Platypus is a web application for managing AWS Systems Manager Parameter Store
parameters and Secrets Manager secrets. Teams can update application
configuration through a shared interface without needing direct AWS access.
Policies control access, and an audit trail records every action.

- Sign in with your identity provider through OpenID Connect or an
  authentication proxy.
- Grant teams or individual users permission to list, create, edit, or reveal
  items by name pattern. Values stay hidden until explicitly revealed.
- Require a passkey or authenticator app for administrative actions. Admin
  mode does not grant access to values.
- Keep parameter and secret values out of the database, logs, and error
  messages.

See the [screenshots](docs/screenshots.md) for a tour of the interface. The
in-app documentation covers everyday use, access policies, and administration.

## Try it locally

The local environment uses Docker Compose, an AWS emulator, and test users.
You do not need an AWS account or an identity provider. The bootstrap command
also requires Make.

```sh
docker compose up --build
```

In another terminal, retrieve the setup token:

```sh
make dev-bootstrap-token
```

Open <http://admin.localhost:8090>, enter the token, and follow the setup
steps to register an authenticator app. Two additional test users are
available at <http://editor.localhost:8090> and <http://nobody.localhost:8090>.
The local proxy assigns an identity to each hostname, and the AWS emulator
contains sample parameters and secrets.

To try OpenID Connect with Dex, add `127.0.0.1 dex` to `/etc/hosts`, then run:

```sh
docker compose --profile oidc up --build
```

Open <http://localhost:8094> and sign in as `olivia@example.com` with the
development password `platypus-dev`.

## Installation

Platypus is available as a container image, Helm chart, or release archive.
Pin a release version for production; `latest` is a moving build of `main`.

- **Container:** `ghcr.io/fliphess/platypus:<version>`, for Linux on amd64
  and arm64.
- **Helm chart:** install from the OCI registry with your deployment values:

  ```sh
  helm install platypus oci://ghcr.io/fliphess/charts/platypus --version <version> -f my-values.yaml
  ```

- **Binary:** release archives are named
  `platypus_<version>_<os>_<arch>.tar.gz`, with checksums provided. Linux and
  macOS builds are available for amd64 and arm64. Extract the archive and run
  `./platypus web` from its directory after configuring the environment. Keep
  the included templates, static files, and documentation alongside the binary.

A production deployment needs PostgreSQL, an AWS IAM role, and an identity
provider or authentication proxy. The Helm chart uses your existing database
and gateway. Follow the [deployment checklist](docs/deployment-checklist.md)
for authentication, permissions, migrations, and initial setup. Example Helm
values are available in [charts/platypus/ci](charts/platypus/ci/).

Configuration uses environment variables. The
[configuration reference](internal/docs/pages/90-configuration.txt) lists
every setting and its default. See [runtime files](docs/assets.md) when
running a binary outside the supplied container image or release archive.

## Documentation

- [Screenshots](docs/screenshots.md): a tour of the application.
- [Deployment checklist](docs/deployment-checklist.md): requirements and
  setup for a production deployment.
- [Threat model](docs/threat-model.md): security boundaries, protections,
  and accepted risks.
- [Reporting a security issue](docs/security.md): reporting instructions
  and the security support policy.
- [Runtime files](docs/assets.md): templates, static assets, and custom
  in-app documentation.
- [UI conventions](docs/ui.md): design and interaction guidelines for
  contributors.

Release changes are listed in the [changelog](CHANGELOG.md).

## Development

Building from source requires Go 1.26 or newer. Run `make build` to create
`bin/platypus`. For cross-compilation, set `GOOS` and `GOARCH`, for example:

```sh
GOOS=linux GOARCH=arm64 go build ./cmd/platypus
```

The application loads its interface from disk. See [runtime
files](docs/assets.md) for the directories required to run a source build.

Common development commands:

```sh
make test-deps   # Start PostgreSQL and the AWS emulator in Docker
make test        # Run all tests with the race detector
make lint        # Run golangci-lint and govulncheck
make generate    # Regenerate code and docs after SQL or configuration changes
make smoke       # Check startup against a fresh database
make e2e         # Run browser tests in Docker
```

Run `make verify` for the full verification suite and `make visual` to
compare the interface with its visual baselines. Use `make screenshots` to
refresh the [documentation images](docs/screenshots.md).

## License

Platypus is licensed under the [MIT License](LICENSE).
