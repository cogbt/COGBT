cogbt_ss = ss.source_set()
cogbt_ss.add(files(
  'translation-unit.cpp',
))

subdir('interfaces')

specific_ss.add_all(when: 'CONFIG_COGBT', if_true: cogbt_ss)
