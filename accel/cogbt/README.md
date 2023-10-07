# COGBT 相关文件介绍
.
├── AOT
│   ├── aot-parser.cpp
│   └── meson.build
├── cogbt.cpp
├── emulator.c
├── helpers.symbols             将QEMU的helper函数暴露到`.dynsym`段以便LLVM的MCJIT
├── host-info.cpp
├── include
│   ├── aot-parser.h            定义`AOTParser`类，解析aot文件
│   ├── cogbt-debug.h           定义了COGBT的debug模式功能
│   ├── cogbt.h                 暴露cpp文件函数给QEMU(c)使用
│   ├── emulator.h              包装QEMU(c)函数给cpp文件使用
│   ├── guest-config.h          guest架构信息基类
│   ├── host-info.h             host架构相关信息
│   ├── jit-eventlistener.h     LLVM MCJIT相关定义
│   ├── llvm-translator.h       定义了`LLVMTranslator`基类
│   ├── memory-manager.h        LLVM 生成代放置内存管理模块
│   ├── translation-unit.h      定义`TranslationUnit`类，一个翻译单元可以理解为LLVM的一个Module
│   ├── x86-config.h            x86作为guest的架构信息
│   ├── x86-inst.def            定义了x86指令的编码，来自于capstone v5.0.0(git fee83fcc1ad096c22d4f2066ccb58ad1a76a9886)
│   ├── x86-inst-handler.h      定义了x86指令处理类，使用该类的目的是为了解耦合x86指令和操作
│   ├── x86-opnd-handler.h      定义了x86数据处理类，使用该类的目的是为了解耦合x86操作数和操作
│   └── x86-translator.h        定义了`X86Translator`类
├── interfaces
│   ├── block
│   │   ├── block.cpp           tb模式下的处理逻辑
│   │   └── meson.build
│   ├── tu
│   │   ├── elf-handle.cpp      elf文件解析逻辑
│   │   ├── tu.cpp              tu模式下的处理逻辑
│   │   ├── json-handle.cpp     COGBT中所用到的json文件解析逻辑
│   │   └── meson.build
│   ├── include
│   │   ├── block.h
│   │   ├── frontend.h          包含了各种静态前端需要用到的函数(如elf parser, json parser, json_func handler, ...)
│   │   ├── json_function.h     定义了`JsonFunc`类，该类是整个静态端解析或者保存信息的基本。
│   │   │                       注意: 除一些特殊情况外，`JsonFunc`类总是与LLVM IR Function一一对应。
│   │   └── json.hpp            来自于来源仓库[1]
│   └── meson.build
├── JIT
│   ├── jit-eventlistener.cpp
│   ├── memory-manager.cpp
│   └── meson.build
├── meson.build
├── optimization_passes         自定义的一些优化pass
│   ├── andi-reduction
│   │   ├── andi-reduction.cpp
│   │   └── CMakeLists.txt
│   ├── CMakeLists.txt
│   ├── flag-reduction
│   │   ├── CMakeLists.txt
│   │   ├── cogbt-x86-flag.h
│   │   └── flag-reduction.cpp
│   ├── pattern
│   │   ├── CMakeLists.txt
│   │   ├── cogbt-x86-flag.h
│   │   └── pattern-reduction.cpp
│   └── sext-reduction
│       ├── CMakeLists.txt
│       └── sext-reduction.cpp
├── translation-unit.cpp
└── translator
    ├── cogbt-debug.cpp
    ├── llvm-translator.cpp
    ├── meson.build
    └── X86
        ├── meson.build
        ├── misc.cpp
        ├── x86-arith.cpp
        ├── x86-bt.cpp
        ├── x86-config.cpp
        ├── x86-cti.cpp
        ├── x86-fpu.cpp
        ├── x86-inst-handler.cpp
        ├── x86-logic.cpp
        ├── x86-mov.cpp
        ├── x86-opnd-handler.cpp
        ├── x86-setcc.cpp
        ├── x86-simd.cpp
        ├── x86-simd-cvt.cpp
        ├── x86-string.cpp
        └── x86-translator.cpp


## 致谢
[1] json解析核心逻辑使用了开源仓库 `https://github.com/nlohmann/json`
