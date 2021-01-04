env = environment()
env.set('G_TEST_SRCDIR', meson.current_source_dir())
env.set('G_TEST_BUILDDIR', meson.build_root())
env.set('SOFTHSM2_CONF', meson.build_root() / 'softhsm2.conf')
env2 = env
env2.set('SOFTHSM2_CONF', meson.build_root() / 'softhsm2-no-raw.conf')

pkcs11_tool_dep = find_program('pkcs11-tool', required: false)
p11tool_dep = find_program('p11tool', required: false)
modutil_dep = find_program('modutil', required: false)
openssl_dep = find_program('openssl', required: false)
softhsm_util_dep = find_program('softhsm2-util', required: false)

libcacard_test = executable(
  'libcacard',
  ['libcacard.c', 'common.c'],
  objects: libcacard.extract_all_objects(),
  dependencies: [libcacard_dep],
)

test(
  'libcacard',
  libcacard_test,
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

initialize_test = executable(
  'initialize',
  ['initialize.c'],
  objects: libcacard.extract_all_objects(),
  dependencies: [libcacard_dep],
)

test(
  'initialize',
  initialize_test,
  env: env,
)

hwtests_test = executable(
  'hwtests',
  ['hwtests.c', 'common.c'],
  objects: libcacard.extract_all_objects(),
  dependencies: [libcacard_dep],
)

if pkcs11_tool_dep.found() and p11tool_dep.found() and modutil_dep.found() and openssl_dep.found() and softhsm_util_dep.found()
  softhsm = custom_target(
    'softhsm2.conf',
    command: find_program('setup-softhsm2.sh'),
    capture: true,
    output: 'setup-softhsm2.log',
  )

  test(
    'hwtests',
    hwtests_test,
    depends: [softhsm],
    env: env,
  )

  # again with different softhsm configuration not allowing raw RSA signatures */
  test(
    'hwtests_no_raw',
    hwtests_test,
    depends: [softhsm],
    env: env2,
  )
endif
