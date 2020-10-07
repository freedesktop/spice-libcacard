env = environment()
env.set('G_TEST_SRCDIR', meson.current_source_dir())
env.set('G_TEST_BUILDDIR', meson.build_root())

fuzz_targets = [
  'fuzz_xfer',
  'fuzz_simpletlv',
  'fuzz_options',
]

deps = [libcacard_dep]

extra_sources = []
extra_c_args = []

fuzzing_engine = cxx.find_library('FuzzingEngine', required: false)
if fuzzing_engine.found()
  deps += fuzzing_engine
else
  extra_sources += 'fuzzer.c'
endif

foreach target_name : fuzz_targets
  exe = executable(target_name, [extra_sources, target_name + '.c'],
    objects: libcacard.extract_all_objects(),
    c_args : extra_c_args,
    dependencies : deps,
  )
  test(target_name, exe,
    args: [meson.current_source_dir() + '/corpora/' + target_name + '/test'],
    env: env,
  )
endforeach
