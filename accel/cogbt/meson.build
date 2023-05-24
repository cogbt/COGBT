cogbt_ss = ss.source_set()

# llvm_dep = dependency('llvm', version : '>=8.0')
llvm_dep = meson.get_compiler('cpp').find_library('LLVM-8',
	dirs: '/home/loongson/llvm_install_cross/lib',
	required: true)
pass_dep = meson.get_compiler('cpp').find_library('LLVMCustomReduction',
	dirs: '/home/loongson/llvm_install_cross/lib',
	required: true)
cogbt_ss.add(llvm_dep)
cogbt_ss.add(pass_dep)

cogbt_ss.add(files(
  'translation-unit.cpp',
  'host-info.cpp',
  'cogbt.cpp',
  'emulator.c',
))

subdir('interfaces')
subdir('translator')
subdir('JIT')
subdir('AOT')

specific_ss.add_all(when: 'CONFIG_COGBT', if_true: cogbt_ss)
