How to contribute to libcacard
==============================

The libcacard is part of SPICE project now so most of the guidelines apply
also here. See
[SPICE developer documentation](https://www.spice-space.org/developers.html)
for more information.


Bug reports, feature requests
=============================

To submit a bug report or a feature requests, use a issue tracker in
[libcacard project](https://gitlab.freedesktop.org/spice/libcacard/issues)
on freedesktop gitlab instance.

Don't forget to include version of libcacard you are using (on RPM based
systems `rpm -q libcacard`), debug logs (collected with
`G_MESSAGES_DEBUG=libcacard LIBCACARD_DEBUG=1`). For example, if you
experience issues with `remote-viewer` linked with spice using libcacard,
start the `remote-viewer` like this to collect debug logs (they will be
printed on stderr):

```
$  G_MESSAGES_DEBUG=libcacard LIBCACARD_DEBUG=1 remote-viewer --spice-smartcard [URI or /path/to/console.vv]
```


Security Issues
===============

If you believe your issue has security consequences, mark the issue as such
in gitlab or contact directly either Jakub Jelen <jjelen@redhat.com> or
Frediano Ziglio <fziglio@redhat.com>.


Submitting Patches
==================

The libcacard follows the
[SPICE project coding style](https://www.spice-space.org/spice-project-coding-style-and-coding-conventions.html).

The libcacard is using git source control versioning. Make sure to create
small self-contained commits with good description. The commits need explicit
`Sign-off-by:` tag and need to be peer reviewed before merging.

The patches can be submitted either through
[gitlab merge requests](https://gitlab.freedesktop.org/spice/libcacard/merge_requests)
or through
[spice-devel mailing list](https://lists.freedesktop.org/mailman/listinfo/spice-devel).
The first option is preferred as it automatically runs the tests on your code
and catches most obvious issues.

New features are required to be covered with tests. Bug fixes are recommended
to provide regression tests if the issue can be simply isolated and tested.
