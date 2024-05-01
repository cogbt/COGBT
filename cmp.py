# RAX=0000000000000000 RBX=0000000000000000 RCX=0000000000000000 RDX=0000000000000000
# RSI=0000000000000000 RDI=0000000000000000 RBP=0000000000000000 RSP=0000004000803240
# R8 =0000000000000000 R9 =0000000000000000 R10=0000000000000000 R11=0000000000000000
# R12=0000000000000000 R13=0000000000000000 R14=0000000000000000 R15=0000000000000000
# RIP=000000000040014d RFL=00000202 [-------] CPL=3 II=0 A20=1 SMM=0 HLT=0
# FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
# FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
# FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
# FPR4=0000000000000000 0000 FPR5=0000000000000000 0000
# FPR6=0000000000000000 0000 FPR7=0000000000000000 0000
# XMM00=0000000000000000 0000000000000000 XMM01=0000000000000000 0000000000000000
# XMM02=0000000000000000 0000000000000000 XMM03=0000000000000000 0000000000000000
# XMM04=0000000000000000 0000000000000000 XMM05=0000000000000000 0000000000000000
# XMM06=0000000000000000 0000000000000000 XMM07=0000000000000000 0000000000000000
# XMM08=0000000000000000 0000000000000000 XMM09=0000000000000000 0000000000000000
# XMM10=0000000000000000 0000000000000000 XMM11=0000000000000000 0000000000000000
# XMM12=0000000000000000 0000000000000000 XMM13=0000000000000000 0000000000000000
# XMM14=0000000000000000 0000000000000000 XMM15=0000000000000000 0000000000000000

# RAX=0000000000000000 RBX=0000000000000000 RCX=0000000000000000 RDX=0000000000000000
# RSI=0000000000000000 RDI=0000000000000000 RBP=0000000000000000 RSP=0000004000803240
# R8 =0000000000000000 R9 =0000000000000000 R10=0000000000000000 R11=0000000000000000
# R12=0000000000000000 R13=0000000000000000 R14=0000000000000000 R15=0000000000000000
# RIP=000000000040014d RFL=00000202 [-------] CPL=3 II=0 A20=1 SMM=0 HLT=0
# ES =0000 0000000000000000 00000000 00000000
# CS =0033 0000000000000000 ffffffff 00effb00 DPL=3 CS64 [-RA]
# SS =002b 0000000000000000 ffffffff 00cff300 DPL=3 DS   [-WA]
# DS =0000 0000000000000000 00000000 00000000
# FS =0000 0000000000000000 00000000 00000000
# GS =0000 0000000000000000 00000000 00000000
# LDT=0000 0000000000000000 0000ffff 00008200 DPL=0 LDT
# TR =0000 0000000000000000 0000ffff 00008b00 DPL=0 TSS64-busy
# GDT=     0000004000808000 0000007f
# IDT=     0000004000804000 000001ff
# CR0=80010001 CR2=0000000000000000 CR3=0000000000000000 CR4=00000220
# DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000
# DR6=00000000ffff0ff0 DR7=0000000000000400
# CCS=0000000000000000 CCD=0000000000000000 CCO=EFLAGS
# EFER=0000000000000500
# FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
# FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
# FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
# FPR4=0000000000000000 0000 FPR5=0000000000000000 0000
# FPR6=0000000000000000 0000 FPR7=0000000000000000 0000
# XMM00=0000000000000000 0000000000000000 XMM01=0000000000000000 0000000000000000
# XMM02=0000000000000000 0000000000000000 XMM03=0000000000000000 0000000000000000
# XMM04=0000000000000000 0000000000000000 XMM05=0000000000000000 0000000000000000
# XMM06=0000000000000000 0000000000000000 XMM07=0000000000000000 0000000000000000
# XMM08=0000000000000000 0000000000000000 XMM09=0000000000000000 0000000000000000
# XMM10=0000000000000000 0000000000000000 XMM11=0000000000000000 0000000000000000
# XMM12=0000000000000000 0000000000000000 XMM13=0000000000000000 0000000000000000
# XMM14=0000000000000000 0000000000000000 XMM15=0000000000000000 0000000000000000

from IPython import embed
import subprocess
import struct

def count_lines_using_wc(file_path):
    result = subprocess.run(['wc', '-l', file_path], stdout=subprocess.PIPE, text=True)
    return int(result.stdout.split()[0])

def read_n_lines(f, n):
    lines = []
    for _ in range(n):
        line = f.readline()
        if not line:
            print("EOF")
            exit(0)
        lines.append(line.strip())
    return lines

def lines_to_fpu(lines, fpu_st, fp_len):
    rip = lines[4].split(" ")[0].split("=")[1]
    st = int(lines[fpu_st].split(" ")[2][4])
    if fp_len == 64:
        fpr0 = lines[fpu_st+1].split(" ")[0].split("=")[1]
        fpr1 = lines[fpu_st+1].split(" ")[2].split("=")[1]
        fpr2 = lines[fpu_st+2].split(" ")[0].split("=")[1]
        fpr3 = lines[fpu_st+2].split(" ")[2].split("=")[1]
        fpr4 = lines[fpu_st+3].split(" ")[0].split("=")[1]
        fpr5 = lines[fpu_st+3].split(" ")[2].split("=")[1]
        fpr6 = lines[fpu_st+4].split(" ")[0].split("=")[1]
        fpr7 = lines[fpu_st+4].split(" ")[2].split("=")[1]
    elif fp_len == 80:
        fpr0 = lines[fpu_st+1].split(" ")[1] + lines[fpu_st+1].split(" ")[0].split("=")[1]
        fpr1 = lines[fpu_st+1].split(" ")[3] + lines[fpu_st+1].split(" ")[2].split("=")[1]
        fpr2 = lines[fpu_st+2].split(" ")[1] + lines[fpu_st+2].split(" ")[0].split("=")[1]
        fpr3 = lines[fpu_st+2].split(" ")[3] + lines[fpu_st+2].split(" ")[2].split("=")[1]
        fpr4 = lines[fpu_st+3].split(" ")[1] + lines[fpu_st+3].split(" ")[0].split("=")[1]
        fpr5 = lines[fpu_st+3].split(" ")[3] + lines[fpu_st+3].split(" ")[2].split("=")[1]
        fpr6 = lines[fpu_st+4].split(" ")[1] + lines[fpu_st+4].split(" ")[0].split("=")[1]
        fpr7 = lines[fpu_st+4].split(" ")[3] + lines[fpu_st+4].split(" ")[2].split("=")[1]
        # fpr2 = lines[fpu_st+2].split(" ")[0].split("=")[1]
        # fpr3 = lines[fpu_st+2].split(" ")[2].split("=")[1]
        # fpr4 = lines[fpu_st+3].split(" ")[0].split("=")[1]
        # fpr5 = lines[fpu_st+3].split(" ")[2].split("=")[1]
        # fpr6 = lines[fpu_st+4].split(" ")[0].split("=")[1]
        # fpr7 = lines[fpu_st+4].split(" ")[2].split("=")[1]
    else:
        raise ValueError("fp_len should be 64 or 80")
    fprs = [fpr0, fpr1, fpr2, fpr3, fpr4, fpr5, fpr6, fpr7]
    strs = [fprs[(i + st)%8] for i in range(8)]
    if fp_len == 80:
        strs = [parse_80_bit_floating_point(s) for s in strs]
    elif fp_len == 64:
        strs = [struct.unpack('!d', bytes.fromhex(s))[0] for s in strs]
    return rip, strs

def parse_80_bit_floating_point(hex_string):
    # 转换十六进制字符串为整数
    int_value = int(hex_string, 16)

    # 1 位符号，15 位指数，64 位尾数
    sign = (int_value >> 79) & 1
    exponent = (int_value >> 64) & 0x7FFF
    significand = int_value & ((1 << 64) - 1)

    # 计算实际的浮点数
    if exponent == 0:
        if significand == 0:
            return -0.0 if sign else 0.0
        else:
            # 非规格化数（denormalized number）
            return (-1) ** sign * significand / (2 ** 63) * (2 ** (1 - 16383))
    elif exponent == 0x7FFF:
        if significand == 0:
            return float('-inf') if sign else float('inf')
        else:
            return float('nan')  # Not a number
    else:
        # 规格化数（normalized number）
        return (-1) ** sign * (significand / (2 ** 63)) * (2 ** (exponent - 16383))

my_file_name = "test.cogbt.log"
my_line_num = count_lines_using_wc(my_file_name)

my_log = open(my_file_name)
qemu_log = open("test.qemu.log")
curr_my_line_num = 0
for i in range(10000):
    my_lines = read_n_lines(my_log, 18)
    qemu_lines = read_n_lines(qemu_log, 33)
    my_rip, my_fpu = lines_to_fpu(my_lines, 5, 64)
    qemu_rip, qemu_fpu = lines_to_fpu(qemu_lines, 20, 80)
    while my_rip != qemu_rip:
        print(f"my_rip: {my_rip}, qemu_rip: {qemu_rip}")
        qemu_lines = read_n_lines(qemu_log, 33)
        qemu_rip, qemu_fpu = lines_to_fpu(qemu_lines, 20, 80)
    if my_fpu != qemu_fpu:
        # hex_value = "e0a3d70a3d70a000"
        # bin_value = bytes.fromhex(hex_value)
        # float_value = struct.unpack('!d', bin_value)[0]
        # float_value
        embed()
        import time
        time.sleep(1)
    curr_my_line_num += 18
    print(f"{curr_my_line_num}/{my_line_num}, {curr_my_line_num/my_line_num*100:.2f}%")
my_log.close()
qemu_log.close()
