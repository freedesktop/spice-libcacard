How to do a libcacard release
=============================

Some notes to prepare a release, not really strict but better to have in order
to avoid forgetting something.

* Update `NEWS` with list of changes done since last release
* Send a merge request with such changes, handle the review
* Try to build an RPM package from `make dist` output (see below notes
  on how to build a source tarball)
* `git push` for the above MR
* `git push` for the version tag created (for instance you can use
  `git push origin v2.8.0` or `git push --tags`)
* Send an email to spice-devel mailing list
* Sign generated tarball (to create a detached signature run
  `gpg2 -sb libcacard-2.8.0.tar.xz`)
* On Gitlab update tags (https://gitlab.freedesktop.org/spice/libcacard/-/tags)
  * Add ChangeLog information
  * Upload tarball and relative signature
* Upload tarball and relative signature to
  https://www.spice-space.org/download/libcacard/ (sftp to
  `spice-uploader@spice-web.osci.io:/var/www/www.spice-space.org/download/libcacard/`)

How to build a source tarball
-----------------------------

1. `git tag -a v2.8.0 -m 'libcacard 2.8.0'` (replace the version)
2. `git clone https://gitlab.freedesktop.org/spice/libcacard.git`
3. `cd libcacard`
4. `./autogen.sh`
5. `make dist`

