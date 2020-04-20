fuzz_targets = [
  'fuzz_xfer',
  'fuzz_simpletlv',
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
  executable(target_name, [extra_sources, target_name + '.c'],
    objects: libcacard.extract_all_objects(),
    c_args : extra_c_args,
    dependencies : deps,
  )
endforeach
