# Buildx

[![GitHub release](https://img.shields.io/github/release/docker/buildx.svg?style=flat-square)](https://github.com/docker/buildx/releases/latest)
[![PkgGoDev](https://img.shields.io/badge/go.dev-docs-007d9c?style=flat-square&logo=go&logoColor=white)](https://pkg.go.dev/github.com/docker/buildx)
[![Build Status](https://img.shields.io/github/actions/workflow/status/docker/buildx/build.yml?branch=master&label=build&logo=github&style=flat-square)](https://github.com/docker/buildx/actions?query=workflow%3Abuild)
[![Go Report Card](https://goreportcard.com/badge/github.com/docker/buildx?style=flat-square)](https://goreportcard.com/report/github.com/docker/buildx)
[![codecov](https://img.shields.io/codecov/c/github/docker/buildx?logo=codecov&style=flat-square)](https://codecov.io/gh/docker/buildx)

Buildx is a Docker CLI plugin for extended build capabilities with
[BuildKit](https://github.com/moby/buildkit).

> [!TIP]
> **Key features**
> - Familiar UI from `docker build`
> - Full BuildKit capabilities with container driver
> - Multiple builder instance support
> - Multi-node builds for cross-platform images
> - Compose build support
> - High-level builds with [Bake](https://docs.docker.com/build/bake/)
> - In-container driver support (both Docker and Kubernetes)

___

- [Installing](#installing)
  - [Windows and macOS](#windows-and-macos)
  - [Linux packages](#linux-packages)
  - [Manual download](#manual-download)
  - [Dockerfile](#dockerfile)
- [Building](#building)
- [Getting started](#getting-started)
  - [Building with Buildx](#building-with-buildx)
  - [Working with builder instances](#working-with-builder-instances)
  - [Building multi-platform images](#building-multi-platform-images)
- [Reference](docs/reference/buildx.md)
- [Contributing](#contributing)

## Installing

Using Buildx with Docker requires Docker engine 19.03 or newer.

> [!WARNING]
> Using an incompatible version of Docker may result in unexpected behavior,
> and will likely cause issues, especially when using Buildx builders with more
> recent versions of BuildKit.

### Windows and macOS

Docker Buildx is included in [Docker Desktop](https://docs.docker.com/desktop/)
for Windows and macOS.

### Linux packages

Docker Engine package repositories contain Docker Buildx packages when installed according to the
[Docker Engine install documentation](https://docs.docker.com/engine/install/). Install the
`docker-buildx-plugin` package to install the Buildx plugin.

### Manual download

> [!IMPORTANT]
> This section is for unattended installation of the Buildx component. These
> instructions are mostly suitable for testing purposes. We do not recommend
> installing Buildx using manual download in production environments as they
> will not be updated automatically with security updates.
>
> On Windows and macOS, we recommend that you install [Docker Desktop](https://docs.docker.com/desktop/)
> instead. For Linux, we recommend that you follow the [instructions specific for your distribution](#linux-packages).

You can also download the latest binary from the [GitHub releases page](https://github.com/docker/buildx/releases/latest).

Rename the relevant binary and copy it to the destination matching your OS:

| OS      | Binary name         | Destination folder                  |
|---------|---------------------|-------------------------------------|
| Linux   | `docker-buildx`     | `$HOME/.docker/cli-plugins`         |
| macOS   | `docker-buildx`     | `$HOME/.docker/cli-plugins`         |
| Windows | `docker-buildx.exe` | `%USERPROFILE%\.docker\cli-plugins` |

Or copy it into one of these folders for installing it system-wide.

On Unix environments:

* `/usr/local/lib/docker/cli-plugins` OR `/usr/local/libexec/docker/cli-plugins`
* `/usr/lib/docker/cli-plugins` OR `/usr/libexec/docker/cli-plugins`

On Windows:

* `C:\ProgramData\Docker\cli-plugins`
* `C:\Program Files\Docker\cli-plugins`

> [!NOTE]
> On Unix environments, it may also be necessary to make it executable with `chmod +x`:
> ```shell
> $ chmod +x ~/.docker/cli-plugins/docker-buildx
> ```

### Dockerfile

Here is how to install and use Buildx inside a Dockerfile through the
[`docker/buildx-bin`](https://hub.docker.com/r/docker/buildx-bin) image:

```dockerfile
# syntax=docker/dockerfile:1
FROM docker
COPY --from=docker/buildx-bin /buildx /usr/libexec/docker/cli-plugins/docker-buildx
RUN docker buildx version
```

## Building

```console
# Buildx 0.6+
$ docker buildx bake "https://github.com/docker/buildx.git"
$ mkdir -p ~/.docker/cli-plugins
$ mv ./bin/build/buildx ~/.docker/cli-plugins/docker-buildx

# Docker 19.03+
$ DOCKER_BUILDKIT=1 docker build --platform=local -o . "https://github.com/docker/buildx.git"
$ mkdir -p ~/.docker/cli-plugins
$ mv buildx ~/.docker/cli-plugins/docker-buildx

# Local
$ git clone https://github.com/docker/buildx.git && cd buildx
$ make install
```

## Getting started

### Building with Buildx

Buildx is a Docker CLI plugin that extends the `docker build` command with the
full support of the features provided by [Moby BuildKit](https://docs.docker.com/build/buildkit/)
builder toolkit. It provides the same user experience as `docker build` with
many new features like creating scoped builder instances and building against
multiple nodes concurrently.

After installation, Buildx can be accessed through the `docker buildx` command
with Docker 19.03. `docker buildx build` is the command for starting a new
build. With Docker versions older than 19.03 Buildx binary can be called
directly to access the `docker buildx` subcommands.

```console
$ docker buildx build .
[+] Building 8.4s (23/32)
 => ...
```

Buildx will always build using the BuildKit engine and does not require
`DOCKER_BUILDKIT=1` environment variable for starting builds.

The `docker buildx build` command supports features available for `docker build`,
including features such as outputs configuration, inline build caching, and
specifying target platform. In addition, Buildx also supports new features that
are not yet available for regular `docker build` like building manifest lists,
distributed caching, and exporting build results to OCI image tarballs.

Buildx is flexible and can be run in different configurations that are exposed
through various [drivers](https://docs.docker.com/build/builders/drivers/).
Each driver defines how and where a build should run, and have different
feature sets.

We currently support the following drivers:
- The `docker` driver ([manual](https://docs.docker.com/build/builders/drivers/docker/))
- The `docker-container` driver ([manual](https://docs.docker.com/build/builders/drivers/docker-container/))
- The `kubernetes` driver ([manual](https://docs.docker.com/build/drivers/kubernetes/))
- The `remote` driver ([manual](https://docs.docker.com/build/builders/drivers/remote/))

For more information, see the [builders](https://docs.docker.com/build/builders/)
and [drivers](https://docs.docker.com/build/builders/drivers/) guide.

> [!NOTE]
> For more information, see [Docker Build docs](https://docs.docker.com/build/concepts/overview/).

### Working with builder instances

By default, Buildx will initially use the `docker` driver if it is supported,
providing a very similar user experience to the native `docker build`. Note that
you must use a local shared daemon to build your applications.

Buildx allows you to create new instances of isolated builders. This can be
used for getting a scoped environment for your CI builds that does not change
the state of the shared daemon or for isolating the builds for different
projects. You can create a new instance for a set of remote nodes, forming a
build farm, and quickly switch between them.

You can create new instances using the [`docker buildx create`](docs/reference/buildx_create.md)
command. This creates a new builder instance with a single node based on your
current configuration.

To use a remote node you can specify the `DOCKER_HOST` or the remote context name
while creating the new builder. After creating a new instance, you can manage its
lifecycle using the [`docker buildx inspect`](docs/reference/buildx_inspect.md),
[`docker buildx stop`](docs/reference/buildx_stop.md), and
[`docker buildx rm`](docs/reference/buildx_rm.md) commands. To list all
available builders, use [`docker buildx ls`](docs/reference/buildx_ls.md). After
creating a new builder you can also append new nodes to it.

To switch between different builders, use [`docker buildx use <name>`](docs/reference/buildx_use.md).
After running this command, the build commands will automatically use this
builder.

Docker also features a [`docker context`](https://docs.docker.com/engine/reference/commandline/context/)
command that can be used for giving names for remote Docker API endpoints.
Buildx integrates with `docker context` so that all of your contexts
automatically get a default builder instance. While creating a new builder
instance or when adding a node to it, you can also set the context name as the
target.

> [!NOTE]
> For more information, see [Builders docs](https://docs.docker.com/build/builders/).

### Building multi-platform images

BuildKit is designed to work well for building for multiple platforms and not
only for the architecture and operating system that the user invoking the build
happens to run.

When you invoke a build, you can set the `--platform` flag to specify the target
platform for the build output, (for example, `linux/amd64`, `linux/arm64`, or
`darwin/amd64`).

When the current builder instance is backed by the `docker-container` or
`kubernetes` driver, you can specify multiple platforms together. In this case,
it builds a manifest list which contains images for all specified architectures.
When you use this image in [`docker run`](https://docs.docker.com/reference/cli/docker/container/run/)
or [`docker service`](https://docs.docker.com/reference/cli/docker/service/),
Docker picks the correct image based on the node's platform.

You can build multi-platform images using three different strategies that are
supported by Buildx and Dockerfiles:

1. Using the QEMU emulation support in the kernel
2. Building on multiple native nodes using the same builder instance
3. Using a stage in Dockerfile to cross-compile to different architectures

QEMU is the easiest way to get started if your node already supports it (for
example. if you are using Docker Desktop). It requires no changes to your
Dockerfile and BuildKit automatically detects the secondary architectures that
are available. When BuildKit needs to run a binary for a different architecture,
it automatically loads it through a binary registered in the `binfmt_misc`
handler.

For QEMU binaries registered with `binfmt_misc` on the host OS to work
transparently inside containers they must be registered with the `fix_binary`
flag. This requires a kernel >= 4.8 and binfmt-support >= 2.1.7. You can check
for proper registration by checking if `F` is among the flags in
`/proc/sys/fs/binfmt_misc/qemu-*`. While Docker Desktop comes preconfigured
with `binfmt_misc` support for additional platforms, for other installations
it likely needs to be installed using [`tonistiigi/binfmt`](https://github.com/tonistiigi/binfmt)
image.

```console
$ docker run --privileged --rm tonistiigi/binfmt --install all
```

Using multiple native nodes provide better support for more complicated cases
that are not handled by QEMU and generally have better performance. You can
add additional nodes to the builder instance using the `--append` flag.

Assuming contexts `node-amd64` and `node-arm64` exist in `docker context ls`;

```console
$ docker buildx create --use --name mybuild node-amd64
mybuild
$ docker buildx create --append --name mybuild node-arm64
$ docker buildx build --platform linux/amd64,linux/arm64 .
```

Finally, depending on your project, the language that you use may have good
support for cross-compilation. In that case, multi-stage builds in Dockerfiles
can be effectively used to build binaries for the platform specified with
`--platform` using the native architecture of the build node. A list of build
arguments like `BUILDPLATFORM` and `TARGETPLATFORM` is available automatically
inside your Dockerfile and can be leveraged by the processes running as part
of your build.

```dockerfile
# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:alpine AS build
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM" > /log
FROM alpine
COPY --from=build /log /log
```

You can also use [`tonistiigi/xx`](https://github.com/tonistiigi/xx) Dockerfile
cross-compilation helpers for more advanced use-cases.

> [!NOTE]
> For more information, see [Multi-platform builds docs](https://docs.docker.com/build/building/multi-platform/).

## Contributing

Want to contribute to Buildx? Awesome! You can find information about
contributing to this project in the [CONTRIBUTING.md](/.github/CONTRIBUTING.md)
