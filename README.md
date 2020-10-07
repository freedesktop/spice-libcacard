# libcacard
[![pipeline status](https://gitlab.freedesktop.org/spice/libcacard/badges/master/pipeline.svg)](https://gitlab.freedesktop.org/spice/libcacard/commits/master)
[![coverage report](https://gitlab.freedesktop.org/spice/libcacard/badges/master/coverage.svg)](https://libcacard.freedesktop.org/)
[![cii best practices](https://bestpractices.coreinfrastructure.org/projects/3465/badge)](https://bestpractices.coreinfrastructure.org/en/projects/3465)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libcacard.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:libcacard)

CAC (Common Access Card) library

This library provides emulation of smart cards to a virtual card
reader running in a guest virtual machine.

It implements DoD CAC standard with separate pki containers
(compatible with coolkey and OpenSC), using certificates read from NSS.

# Documentation

The API documentation is available in
[docs/libcacard.txt](https://gitlab.freedesktop.org/spice/libcacard/blob/master/docs/libcacard.txt)
file.

The libcacard is internally used by spice to emulate and share smart cards
from client system to local or remote VMs. The whole integration image of
smart card sharing can look like this:

```
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                       ~~~~~~~~~~~~~~~~~~~~
~                                                 ~                       ~                  ~
~   +-----+                                       ~                       ~                  ~
~   |     |                   Client              ~                       ~      Server      ~
~   |Smart|                                       ~                       ~                  ~
~ +-|Card |-+                                     ~                       ~                  ~
~ | |     | |                                     ~                       ~ +--------------+ ~
~ | ------- |                                     ~                       ~ |      VM      | ~
~ |  Reader |                                     ~                       ~ | +---------+  | ~
~ +---------+                                     ~                       ~ | | virtual |  | ~
~      |                                          ~                       ~ | |  CCID   |  | ~
~      |                                          ~                       ~ | | device  |  | ~
~ +---------+  +--------+  +-----+  +-----------+ ~                       ~ | +---------+  | ~
~ |  pcscd  |--| OpenSC |--| NSS |--| libcacard | ~                       ~ |   qemu-kvm   | ~
~ +---------+  +--------+  +-----+  +-----------+ ~                       ~ +--------------+ ~
~                                         |       ~                       ~      |           ~
~                                         |       ~                       ~      |           ~
~             +---------------+  +--------------+ ~                       ~ +--------------+ ~
~             | remote-viewer |--| spice-client | ~ <=[ spice channel ]=> ~ | spice-server | ~
~             +---------------+  +--------------+ ~                       ~ +--------------+ ~
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                       ~~~~~~~~~~~~~~~~~~~~
```

In case of smart card emulation, the client side smart card stack is not needed:
```
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                       ~~~~~~~~~~~~~~~~~~~~
~                                     ~                       ~                  ~
~                 Client              ~                       ~      Server      ~
~                                     ~                       ~                  ~
~                                     ~                       ~ +--------------+ ~
~                                     ~                       ~ |      VM      | ~
~                                     ~                       ~ | +---------+  | ~
~                                     ~                       ~ | | virtual |  | ~
~                                     ~                       ~ | |  CCID   |  | ~
~                                     ~                       ~ | | device  |  | ~
~              +-----+  +-----------+ ~                       ~ | +---------+  | ~
~              | NSS |--| libcacard | ~                       ~ |   qemu-kvm   | ~
~              +-----+  +-----------+ ~                       ~ +--------------+ ~
~                             |       ~                       ~      |           ~
~                             |       ~                       ~      |           ~
~ +---------------+  +--------------+ ~                       ~ +--------------+ ~
~ | remote-viewer |--| spice-client | ~ <=[ spice channel ]=> ~ | spice-server | ~
~ +---------------+  +--------------+ ~                       ~ +--------------+ ~
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                       ~~~~~~~~~~~~~~~~~~~~
```

The virtual machine can access the shared or emulated smart card as any other
smart card connected to the system through USB reader. There is no additional
software nor drivers needed so this can work regardless operating system
(assuming there is a driver understanding PC/SC and appropriate middleware
understanding GSC-IS 2.1 CAC specification).

More information about libcacard, see the following links to the SPICE documentation:

* https://www.spice-space.org/smartcard-usage.html
* https://www.spice-space.org/spice-user-manual.html#_cac_smartcard_redirection

There is also documentation in qemu repository, describing how CCID device emulation
works inside of the QEMU:

* https://git.qemu.org/?p=qemu.git;a=blob;f=docs/ccid.txt

# Contributing

To read how to submit a bug or contribute your changes to libcacard, see the
[CONTRIBUTING.md](https://gitlab.freedesktop.org/spice/libcacard/blob/master/CONTRIBUTING.md)
in this repository.

# History

This project used to be part of qemu until version 2.5. The history
has been preserved and it inherits the tags and version.

# Authors

This project was originally developed by:

- Alon Levy <alevy@redhat.com>
- Robert Relyea <rrelyea@redhat.com>

Extended to new GSC-IS 2.1 standard by:

- Jakub Jelen <jjelen@redhat.com>

