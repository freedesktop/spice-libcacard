project('libcacard', 'c', 'cpp',
  version: run_command('build-aux/git-version-gen', '@0@/.tarball-version'.format(meson.source_root()), check: true).stdout().strip(),
  license: 'LGPLv2.1',
  default_options: ['warning_level=2'],
)

meson.add_dist_script('build-aux/meson-dist', meson.project_version(), meson.source_root())

cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')

static_dep = (get_option('default_library') == 'static')

glib_dep = dependency('glib-2.0', version: '>= 2.32', static: static_dep)
nss_dep = dependency('nss', version: '>= 3.12.8', static: static_dep)

pcsc_dep = dependency('libpcsclite', required: get_option('pcsc'))

install_headers([
    'src/cac.h',
    'src/card_7816.h',
    'src/card_7816t.h',
    'src/eventt.h',
    'src/libcacard.h',
    'src/vcard.h',
    'src/vcard_emul.h',
    'src/vcard_emul_type.h',
    'src/vcardt.h',
    'src/vevent.h',
    'src/vreader.h',
    'src/vreadert.h',
    'src/vscard_common.h',
  ],
  subdir: 'cacard',
)

libcacard_src = [
  'src/cac-aca.c',
  'src/cac.c',
  'src/card_7816.c',
  'src/common.c',
  'src/event.c',
  'src/gp.c',
  'src/msft.c',
  'src/simpletlv.c',
  'src/vcard.c',
  'src/vcard_emul_nss.c',
  'src/vcard_emul_type.c',
  'src/vcardt.c',
  'src/vreader.c',
]

if pcsc_dep.found()
  libcacard_src += 'src/capcsc.c'
endif

mapfile = 'src/libcacard.map'
vflag = '-Wl,--version-script,@0@'.format(meson.current_source_dir() / mapfile)

libcacard = library(
  'cacard', libcacard_src,
  dependencies: [glib_dep, nss_dep, pcsc_dep],
  c_args: '-DG_LOG_DOMAIN="libcacard"',
  version: '0.0.0',
  link_args: cc.get_supported_link_arguments([vflag]),
  link_depends: mapfile,
  install: true,
)

libcacard_dep = declare_dependency(
  link_with: libcacard,
  include_directories: [include_directories('.'), include_directories('src')],
  dependencies: [glib_dep, nss_dep, pcsc_dep],
)

executable('vscclient', 'src/vscclient.c', dependencies: [libcacard_dep])

configure_file(
  output: 'config.h',
  configuration: {
    'ENABLE_PCSC': pcsc_dep.found(),
  },
)

pc = import('pkgconfig')
pc.generate(
  libraries: libcacard,
  requires: ['glib-2.0'],
  requires_private: ['nss'],
  subdirs: 'cacard',
  version: meson.project_version(),
  name: 'cacard',
  filebase: 'libcacard',
  description: 'CAC (Common Access Card) library',
)

if not get_option('disable_tests')
  subdir('tests')
endif
subdir('fuzz')
