cogbt_ss = ss.source_set()

# llvm_dep = dependency('llvm', version : '>=8.0')
llvm_dep = meson.get_compiler('cpp').find_library('LLVM',
	dirs: LLVM_HOME + '/lib',
	required: true)
pass_dep = meson.get_compiler('cpp').find_library('LLVMCustomReduction',
	dirs: LLVM_HOME + '/lib',
	required: true)
cogbt_ss.add(llvm_dep)
cogbt_ss.add(pass_dep)

cogbt_ss.add(files(
  'translation-unit.cpp',
  'host-info.cpp',
  'cogbt.cpp',
  'emulator.c',
))

plugin_ldflags = ['-Xlinker', '--dynamic-list=' + (meson.project_source_root()
  / 'accel/cogbt/helpers.symbols')]
cogbt_ss.add(declare_dependency(link_args: plugin_ldflags))

subdir('interfaces')
subdir('translator')
subdir('JIT')
subdir('AOT')

specific_ss.add_all(when: 'CONFIG_COGBT', if_true: cogbt_ss)
