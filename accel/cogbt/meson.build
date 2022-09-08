cogbt_ss = ss.source_set()

llvm_dep = dependency('llvm', version : '>=8.0')
cogbt_ss.add(llvm_dep)

cogbt_ss.add(files(
  'translation-unit.cpp',
  'host-info.cpp',
))

subdir('interfaces')
subdir('translator')
subdir('JIT')

specific_ss.add_all(when: 'CONFIG_COGBT', if_true: cogbt_ss)
