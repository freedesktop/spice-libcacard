# libcacard  [![pipeline status](https://gitlab.freedesktop.org/spice/libcacard/badges/master/pipeline.svg)](https://gitlab.freedesktop.org/spice/libcacard/commits/master) [![coverage report](https://gitlab.freedesktop.org/spice/libcacard/badges/master/coverage.svg)](https://gitlab.freedesktop.org/spice/libcacard/commits/master)

CAC (Common Access Card) library

This library provides emulation of smart cards to a virtual card
reader running in a guest virtual machine.

It implements DoD CAC standard with separate pki containers
(compatible with coolkey and OpenSC), using certificates read from NSS.

For more information and API documentation, read the docs/libcacard.txt file.

# History

This project used to be part of qemu until version 2.5. The history
has been preserved and it inherits the tags and version.

# Authors

This project was originally developped by:

- Alon Levy <alevy@redhat.com>
- Robert Relyea <rrelyea@redhat.com>

Extended to new GSC-IS 2.1 standard by:

- Jakub Jelen <jjelen@redhat.com>

