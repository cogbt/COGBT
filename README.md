# QEMU 优化实验报告

## 实验目的

QEMU 是纯软件实现的虚拟化模拟器，通过建立各平台的状态机模型，几乎可以模拟任何硬件设备，但正因为如此，每条翻译的指令都需要对状态转换时涉及到的大量变量的存取，又因为变量均存储于内存中，运行效率非常低。

本实验的目的便是基于 QEMU 的 AOT 模式，将指令翻译的方式从采用 QEMU 自带的 TCG 改为基于 LLVM 的二次翻译，即先将待翻译的微指令翻译为中间代码 LLVM IR，再由 LLVM IR 转译为目标平台的指令。具体而言，本项目涉及到的指令转换过程为：X86_64（主机，Host）→ LLVM IR（中间指令）→ LoongArch （客户机，Guest ）。

同时，在原指令翻译为 LLVM IR 的过程中实现寄存器映射，使得状态转换时涉及到的大量变量存取的位置由内存更改为寄存器，大大提高指令运行的效率。

> 由于时间原因，寄存器绑定尚未实现，但是已经做好前期准备

## 实验代码概述

实验主要工作目录为 /home/liufengyuan/cogbt-20230702-submit/accel/cogbt，由 Host 翻译到 LLVM IR 的程序代码位于 translator/X86，可参考的 QEMU TCG Helper 程序包括 target/i386 目录，cogbt-20230702-submit/accel/tcg/cpu-exec.c 文件涉及到翻译时 Path 文件的生成。

在本人的项目调试中，使用 e1.c 文件作为调试程序代码，采用 make run 指令测试，对于 dbt5_ut 和 spec 2000 测试用例的测试方式另行介绍。

核心代码：

1. Host 程序分块，由 QEMU 完成。
2. 各程序块 cogbt 翻译初始化，X86Translator::InitializeFunction(StringRef Name)函数，在函数内完成对寄存器的映射。
3. 各微码的翻译代码，如 X86Translator::translate_fadd(GuestInst \*Inst)等。

本人所做的工作主要集中于 accel/cogbt/x86-fpu.cpp|x86simd.cpp|misc.cpp。完成了近 300 条指令的的翻译工作，但并未加入寄存器绑定。

对于寄存器绑定，参考定点数寄存器绑定工作，主要流程如下：

1. 在 x86-config.h 中定义要操作的 X86 Status 变量以及用于绑定的 Guest 寄存器。
2. 在 InitializeFunction 函数中完成绑定操作。
3. 在各指令翻译过程中，操作 X86 Status 变量后，调用 SyncAllGMRValue() 函数进行寄存器 update，类似函数包括 SyncGMRValue，FlushGMRValue，ReloadGMRValue，LoadGMRValue 等等，可按需使用。

在翻译过程中，可能遇到使用 LLVM 提供的函数进行操作较为困难复杂或无法实现的情况，可以编写 helper 实现，在 helper 中可采用所有 C 语法，编写自定义 helper 的方式如下：

1. 在 cogbt/target/i386/helper.h 中，使用 DEF_HELPER\_\* 宏定义声明。
2. LLVM 中注册
   1. 在 emulator.h 声明 wrapper 函数
   2. 在 emulator.c 定义 wrapper 函数
   3. 写入 SymTable
   4. 在 x86-translator.cpp 中添加 Syms
3. 在 /home/liufengyuan/cogbt-20230702-submit/target/i386/helper.c 中用 C 语法编写 helper 函数
4. 在需要调用 helper 的地方使用 CallFunc（）函数调用
   1. 定义 Helper 函数类型
   2. 调用函数

对于 LLVM 中类似于 if 分支跳转的情况，可采用函数块跳转的方式解决，详情参考 GenFCMOVHelper 函数，涉及到的主要函数：BasicBlock::Create, Builder.CreateCondBr, Builder.CreateBr, Builder.SetInsertPoint。

## 实验情况

### FPU 浮点数单元指令翻译

翻译模型主要思想：

1. 完全模拟 X87 FPU 对于浮点数寄存器的出栈入栈操作，控制栈顶指针加减。
2. FPU 浮点数寄存器为存储 80 位扩展双精度浮点数的寄存器，由于 LLVM 无法直接处理 80 位数据的存储，Helper 采用分割为 64+16 的方式，我们在实现时经过讨论采用了直接存储 64 为双精度浮点数数据的方式，即对于浮点数寄存器的操作均只使用低 64 位。
   由于 2 的翻译方式，会导致以下问题：
   a. 对于所有会使用到浮点数的操作都必须转换为 64 位双精度浮点数
   b. 浮点数计算精度损失
   c. 隐藏的 64 位浮点数与 80 位浮点数的相互转换
   对于问题 a，在完成了所有 FPU 指令翻译后基本得到解决，对于问题 b，影响极小，而对于问题 c，主要体现在对于 long double 型变量的存储以及运算上，目前两种浮点数类型转换采用 QEMU Helper 中所提供 softfloat 库的转换函数实现，问题表现为 3.125 此类可精确表示的浮点数可正常转换，3.1 此类不可精确表示的浮点数转换会导致段错误。

对于 dbt5_ut 测例，使用翻译后 FPU 指令的 cogbt 通过了绝大部分测例，进行指令翻译时自行编写的各类 DEMO 也都正确运行，证明所翻译的指令无逻辑错误。

但对于本人所作的 FPU 指令翻译，仍然存在以下问题或不足：

1. 未对 ±∞、±Nan 类型浮点数进行判定和处理
2. 除比较指令外，未根据过程和结果修改 FPU Flags
3. 未根据定义在某些情况下抛出异常 Exceptions（LLVM 可能会进行处理）
4. 未根据 FPU Control Word 设置浮点数运算时的舍入方式
5. 常量载入时未根据 FPU Control Word 载入不同精度的数值
6. 部分指令翻译存在优化空间

## SMID 指令翻译

SIMD(Single Instruction Multiple Data)即单指令流多数据流，X86 架构中包含大量 SIMD 指令，指令集包括 SSE，SSE2，AVX，FMA 等其操作的对象主要为 XMM, YMM, ZMM 寄存器，通常 XMM 即为 ZMM 的低 128 位，YMM 为 ZMM 的低 256 位，ZMM 寄存器共 16 个。

在 X86 架构中，XMM0 将固定作为函数浮点数返回值存放点，从而禁用 SSE 指令是不可能的，任何涉及到浮点数的程序都需要基于 XMM 寄存器，所以为了实现浮点数的完整支持，必须实现部分 SMID 指令。

大部分 SMID 指令，并不复杂，在翻译过程中主要涉及到对 X86_Staus 中 ZMM 变量的处理，包括存取、计算、类型转换等等。小部分 SMID 指令较为复杂，涉及到较多条件语句以及移位、截取操作。

对于简单的指令，本人依照逻辑均成功实现，对于复杂的指令调用了 Helper 进行处理，SMID 指令的翻译集中于 accel/cogbt/translator/X86/misc.cpp|x86-simd.cpp ,对于本人对 SMID 指令的翻译工作，主要不足在于存在较大的优化空间。

另外，将 order 的浮点数以及非 order 的浮点数依照相同情况处理，实质上经过查阅资料，二者不同集中于 X86 平台上对于二者的读取存在差异，但在模拟器上并无不同。

翻译过程中要注意获取指令操作数的顺序问题，部分指令含有四个操作数，需要按文档要求按顺序处理

### SMID 指令翻译高频使用函数

1. getXMMPtr(int i, int start_byte, Type * Ty)
   用于得到指向 XMM[i]所在内存区域的指针，start_byte 控制指针向后移动的字节数，用于获取 XMM 的高 64bit 等操作，Ty 为返回的 Value*类型。
   该函数同样可用于获取 YMM，ZMM 的指针，因为实际上他们和 XMM 共享内存区域，只是大小不同，取决于如何使用所得到的指针。

2. X86OperandHandler.GetXMMID()
   获得 X86OperandHandler 所操作对象的 XMM 寄存器序号，要确保该对象是 XMM 寄存器，可通过 X86OperandHandler.isXMM()判断

3. CalcMemAddr(InstHdl.getOpnd(*))
   用于计算传入的内存变量的地址，常用于对 128 位或 256 位内存变量的切割，注意返回值为存储 Int 的 Value*类型，需要使用 Builder.CreateIntToPtr() 函数进行转换

对于 SMID 会调用的 Helper 函数，主要位于 target/i386/ops_sse.h，通过阅读 Helper 中对 ZMM 寄存器的操作，可以发现，部分指令 Helper 中的实现仅操作了低 128 位，即只修改了 XMM 寄存器，会导致 QEMU 对指令的翻译出现错误。
同时，注意到存在函数 set_float_rounding_mode，可能可以用于解决修改浮点数舍入方式的问题。

### SMID 指令翻译目前存在的问题

1. 部分指令实现不完全，只实现了对 XMM 寄存器的操作而未实现对 YMM，ZMM 寄存器的对应操作。
2. 部分指令未在操作时严格按照 Intel 文档对 XMM 寄存器的未使用位清零，如在操作 XMM 寄存器时，其对应的 ZMM 寄存器的低位作为 XMM 寄存器存取，此时高位应当清零。
3. 存在较大的代码优化空间
4. 没有根据情况设置浮点数 exception flags

## SPEC2000 调试情况

SPEC 2000 是从实际应用程序中提取出来的，大多由 C 语言和 Fortran 语言编写两套基准程序组成，分别测试 CPU 的整型运算性能和浮点运算性能。

对于本项目部署的 SPEC 测试，由跳板机上的 musl-gcc 以及 MinGW 工具链中的 gfortran 编译，得到 x86 平台的代码，在 LoongArch 平台上使用 cogbt 进行翻译运行，以完成对 cogbt 运算性能和浮点运算性能的测试。

SPEC2000 在跳板机中部署于 /home/liufengyuan/spec2000-test，主要用于测例的编译，在 LoongArch 平台部署于~/spec2000，编译运行方式参考下一个章节。

目前在 cogbt 环境下，SPEC2000 成功运行 CINT2000 目录下的定点数测试，对于 CFP2000 目录下的浮点数测试，采用 musl-gcc 编译的测例运行成功，而采用 gfortan 编译的测例由于采用了大量 SMID 指令而无法运行，主要原因如下：

1. 由于对浮点数的处理，在 64bit 与 80bit 浮点数的转换中会出现未知问题
2. 部分 SMID 指令无法在 QEMU 中运行，报错 Illegal instruction
   对于 SPEC2000 有关 SMID 指令错误的最佳解决方式便是将 SPEC2000 编译为不使用 SMID 指令集的程序，但本人进行了一些尝试，均未成功
3. 在 SPEC 编译的 CFLAG 中加入-mmo-avx 等
   对于 musl-gcc 编译的测例有效，对于 gfortan 编译的测例无效，通过反汇编得到的二进制文件显示测例代码成功编译为不含 SMID 指令的程序，但调用的 string 等库包含大量 SMID 指令
4. 重新使用 —disable-avx 等 configuration 重新编译 libc 库
   无效，gfortan 未调用重新编译的库，且由于重新编译 libc 库时依赖于本机的 linux-gcc，其中已经含有大量 SMID 优化指令，无法通过 —disable 去除
5. 重新编译一版 MinGW
   过于复杂，时间问题放弃
6. 编译时在 CFLAGS 添加 -march=<cpu-type> 尝试将代码编译为不含 SMID 指令的 i386 或 westmere 架构程序
   失败原因同 1，在尝试以该方式编译 gcc 与 libc 时不成功，出现各类错误。

虽然本人的尝试均为成功，但思路应当是正确的，因为 SMID 指令出现于 SPEC2000 调用的 libc 库中，只要将 libc 库修改为不含 cogbt 不支持 SMID 指令的库即可实现程序的正常运行，但需要建立较为复杂的交叉编译环境。

## 实验复现

最终代码存放于 ~/cogbt-20230702-submit。

该目录对实验机器和跳板机都适用。

### DBT5_UT

在跳板机 cogbt-20230702-submit 目录下：make test_run TEST_FILE={test name}，会对 DBT5_UT 的测例进行测试。

如 make test_run TEST_FILE=fldst/fld 。

### 运行 SPEC2000 测例

在 loongson 平台用户根目录下使用以下命令查看可运行测例 ./test.sh，测例运行基于 ~/binfmt.sh 和 ~/aot.sh 。

运行时调用的 qemu 程序可在 aot.sh 中修改，目前为 cogbt-20230702-submit 版本，运行结果重定向于 qemu.txt、build.txt、myqemu.txt

### 重新编译 SPEC2000

在跳板机 /home/liufengyuan/spec2000-test/config 目录下的 gcc8-2000-static-musl.cfg 中修改标志位可控制编译选项，但采用 gfortran 编译的测例由于调用的 libc 不参考该选项而无效。

运行 /home/liufengyuan/spec2000-test/config/rebuild_CFP.sh ，可重新编译浮点数测例并在 x86 平台的跳板机上全部运行一次。

编译完成后程序保存在 /home/liufengyuan/spec2000-test/benchspec/CFP2000，需要使用 scp -r CFP2000 5k:~/spec2000-test/benchspec 复制到 loongson 中，便可以采用之前提及的方法运行重新编译后的 spec2000 。

## 存在的问题

1. 部分指令仍调用了 Helper 进行操作
   主要为操作各种状态寄存器的指令以及部分条件非常多的计算指令
2. 部分指令无法在原版 qemu 下运行，导致无法进入到 LLVM 翻译环节，显示 Illegal instruction，导致无法验证，例如 vperm2f128 等一系列 AVX 指令
3. 部分指令仅完成了 spec2000 所需要的 XMM 部分，未完成 YMM、ZMM 部分
   spec2000 本身并没有使用到 YMM、ZMM 部分，是其调用的 String 等库中使用了，所以做了部分翻译，如果找到了方法编译出不使用 AVX、FMA 等指令集的 libc 库应当可以略过这一部分（实际上应当可以实现的，因为早期的 CPU 本来就没有这些指令集，但之前尝试时发现由于编译 libc 依赖了原有的 libc，所以很麻烦）
4. 部分指令原版 qemu 运行的结果与 x86 运行的结果不同，但翻译得到的结果与 x86 相同
   根据目前发现的情况似乎是由于 qemu 把 ymm（256bit）、zmm（512bit）等操作数都当作 xmm（128bit）来做了，而且目前的 qemu 版本似乎和最新的版本并不同
5. 在处理浮点数的所有操作中未判定是否是合法浮点数
   即未判定是否为 inf、nan，如果出现的话，在大小比较和计算时可能会出现问题。后面可以写一个判断的函数或者调用 helper 提供的函数来做判定和不同条件下的分支
6. 在处理所有浮点数运算时，未考虑舍入方式的变化
   spec2000 的测试好像没有涉及舍入的变化，都是在调用的 libc 中自动生成的，似乎并不会有太大的问题。修改舍入方式的操作在之前的尝试中似乎没有效果，就一直搁置了
7. 部分 X86 架构的控制指令置空处理，如对 Cache 的操作、Halt 等
   应该不会有问题
8. 翻译指令的代码仍具有较多的优化空间，例如重复调用相同函数等
9. 由于 5 以及在处理 printf 时采用了 f64-f80 转换，在 print 例如 `3.1` 等无法完全转换的浮点数时会报段错误，只有类似于 `3.5` 的整浮点数可以正常输出
10. 还有相当一部分指令未进行验证，尤其是由于 2 的原因，很多指令无法运行。
