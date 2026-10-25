This document describes the process for compiling n2n in several different
scenarios.

There are some configuration options available during the build process,
which are documented in the [Build time Configuration](BuildConfig.md) page.

Also of use are the steps used for the automated Continuous Integration
process, which can be found in the [Github actions config file](../.github/workflows/tests.yml)

# Git submodules

If you are compiling with the UPnP libraries, it is possible that your
operating system or your build system do not include binaries for the
required libraries.

Using these libraries can cause issues with some build systems, so be
aware that not all combinations are supportable.

To make this scenario simpler, the required source code has been added
to this repository as git `submodules` which require one extra step to
complete their checkout.

So the very first time after cloning the n2n git repo, you should run
this command in the n2n directory to fetch the submodules:

```bash
git submodule update --init --recursive
```

# Build on macOS

macOS builds use the in-kernel `feth` (fake ethernet) driver which is part of
every macOS release since Sierra. No TUN/TAP kernel extension and no helper
service has to be installed, only the command line tools:

```bash
xcode-select --install
```

`edge` needs **root privileges for its whole lifetime** on macOS: creating,
pairing, configuring and destroying the `feth` interfaces as well as opening a
`/dev/bpf*` device are privileged operations. The `-u`/`-g` options (and their
`--euid`/`--egid` forms, also usable in a configuration file) are therefore
rejected on macOS before any interface is created.

Start the edge with `sudo` (a daemonized edge keeps running as root as well):

```bash
sudo edge -c mynetwork -k mysecretpass -a 192.168.100.1 -l supernode.example.org:7654 -f
```

The kernel assigns the interface names, a pair of `fethN` interfaces is created
per edge. Both names are logged at start-up, see
[TAP Device Configuration](./TapConfiguration.md) for details, the DHCP
configuration responsibility and how to clean up a pair left behind by a killed
process.

# Build on Windows

The following document one possible windows compile recipe.  The reason
a MinGW build process is used is it is more friendly to open source
development.

## MinGW

These steps were tested on a fresh install of Windows 10 Pro with all patches
applied as of 2021-09-29.

- Install Chocolatey (Following instructions on https://chocolatey.org/install)
- from an admin cmd prompt
    - `choco install git mingw make`
- Once the git package is installed, you will have a new start menu item
  called "Git Bash".  All the remaining commands must be run from inside the
  shell started by that menu item:
    - `git clone $THIS_REPO`
    - `cd n2n`
    - `./scripts/hack_fakeautoconf.sh`
    - `make`
    - `make test`

Due to limitations in the Windows environment, the normal autotools steps have
been emulated by the `hack_fakeautoconf` - This currently results in the
version number reported by the compiled software being inaccurate.

Note: MinGW builds have had a history of incompatibility reports with other OS
builds (for example [#617](https://github.com/ntop/n2n/issues/617) and [#642](https://github.com/ntop/n2n/issues/642))
However, if the tests pass, you should have a high confidence that your build
will be compatible.

## Run on Windows

In order to run n2n on Windows, you will need the following:

- The TAP drivers should be installed into the system. They can be installed from
  http://build.openvpn.net/downloads/releases, search for "tap-windows".

- If OpenSSL has been linked dynamically, the corresponding `.dll` file should be available
  onto the target computer.

The `edge.exe` program reads the `edge.conf` file located into the current directory if no option is provided.

The `supernode.exe` program reads the `supernode.conf` file located into the current directory if no option is provided.

Example [edge.conf](../packages/etc/n2n/edge.conf.sample)
and [supernode.conf](../packages/etc/n2n/supernode.conf.sample) are available.

See `edge.exe --help` and `supernode.exe --help` for a full list of supported options.

# Cross compiling on Linux

## Using the Makefiles and Autoconf

The Makefiles are all setup to allow cross compiling of this code.  You
will need to have the cross compiler, binutils and any additional libraries
desired installed for the target architecture.  Then you can run the `./configure`
with the appropriate `--host` option.

If compiling on Debian or Ubuntu, this can be as simple as the following example:

```
HOST_TRIPLET=arm-linux-gnueabi
sudo apt-get install binutils-$HOST_TRIPLET gcc-$HOST_TRIPLET
./autogen.sh
./configure --host $HOST_TRIPLET
make
```

A good starting point to determine the host triplet for your destination platform
can be found by copying the `./config.guess` script to it and running it on the
destination.

This is not a good way to produce binaries for embedded environments (like OpenWRT)
as they will often use a different libc environment.

# N2N Packages

There are also some example package build recipes included with the source.

- [Debian](../packages/debian/README)
- [RPM](../packages/rpm)
- [OpenWRT](../packages/openwrt/README.md)
