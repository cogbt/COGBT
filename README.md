# COGBT
本项目基于QEMU 7.0.93 和 LLVM8.0 开发，是一个支持x86 to LoongArch的动静结合的二进制翻译器。

QEMU基于 git (commit a8cc5842b5cb863e46a2d009151c6ccbdecadaba)开发。

LLVM基于 LLVM release/8.x-loongarch (commit 2057f50dd78523679a66429449edfa790e0577ae)开发。

## Quick Start
### Compiler
本仓库在`build-shell`文件夹中默认自带了三个编译脚本。
- `build64.sh`: 生成cogbt可执行文件。
- `build64-dbg.sh`: 生成cogbt可执行文件，相比于第一个其中包含了调试信息。
- `build64-qemu.sh`: 生成qemu的可执行文件，主要逻辑是qemu的逻辑，但是会多生成一个path文件供`tb_aot`模式使用。

第一次编译时可以使用类型命令进行编译`./build64-dbg.sh -c`。编译后会根据编译脚本的不同在项目根目录下生成对应的文件夹，如`build64-dbg/`。

### Running
本项目稳定支持两种执行模式: JIT 和 AOT。JIT模式(类似动态翻译器)，可直接运行。AOT模式(动静结合的混合翻译器)下需要先执行生成`.aot`文件(静态部分)，然后再加载对应的`.aot`文件进行运行(动态部分)。

#### JIT
JIT 模式执行，可直接使用编译生成的可执行文件执行原本的命令。类似`./build64-dbg/qemu-x86_64 coremark.exe 1 1 1 1`。

#### AOT
AOT模式下首先生成`.aot`文件，该文件的生成**通常**只需要原本的可执行文件(guest)，而不需要参数，因为对于guest程序这里采用的是elf静态挖掘技术。

生成`.aot`文件: `./qemu-x86_64 -m <mode> <guest_elf>`
加载`.aot`执行: `./qemu-x86_64 -a <aot_file> <guest_elf> <guest_parameter>`

AOT模式下又可分为多种细化模式。
- tb aot mode: 翻译单元为一个tb。**该模式需要提前准备一个path文件，可以由原生qemu执行一次得到(参考build64-qemu.sh)。**
```
生成aot文件：./build64-dbg/qemu-x86_64 -m tb_aot coremark.exe
执行：./build64-dbg/qemu-x86_64 -a coremark.exe.aot coremark.exe 1 1 1 1
```
- tu aot mode: 翻译单元为多个tb，多个tb形成一个tu采用了一个简单的算法。
```
生成aot文件：./build64-dbg/qemu-x86_64 -m tu_aot coremark.exe
执行：./build64-dbg/qemu-x86_64 -a coremark.exe.aot coremark.exe 1 1 1 1
```

