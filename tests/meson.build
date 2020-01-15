env = environment()
env.set('G_TEST_SRCDIR', meson.current_source_dir())
env.set('G_TEST_BUILDDIR', meson.build_root())
env.set('SOFTHSM2_CONF', meson.build_root() / 'softhsm2.conf')

softhsm = custom_target(
  'softhsm2.conf',
  command: find_program('setup-softhsm2.sh'),
  capture: true,
  output: 'setup-softhsm2.log',
)

libcacard_test = executable(
  'libcacard',
  ['libcacard.c', 'common.c'],
  objects: libcacard.extract_all_objects(),
  dependencies: [libcacard_dep],
)

test(
  'libcacard',
  libcacard_test,
  depends: [softhsm],
  env: env,
)

simpletlv_test = executable(
  'simpletlv',
  ['simpletlv.c'],
  objects: libcacard.extract_all_objects(),
  dependencies: [libcacard_dep],
)

test(
  'simpletlv',
  simpletlv_test,
  env: env,
)

hwtests_test = executable(
  'hwtests',
  ['hwtests.c', 'common.c'],
  objects: libcacard.extract_all_objects(),
  dependencies: [libcacard_dep],
)

test(
  'hwtests',
  hwtests_test,
  depends: [softhsm],
  env: env,
)
