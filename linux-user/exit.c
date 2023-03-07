/*
 *  exit support for qemu
 *
 *  Copyright (c) 2018 Alex Bennée <alex.bennee@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "exec/gdbstub.h"
#include "qemu.h"
#include "user-internals.h"
#ifdef CONFIG_GPROF
#include <sys/gmon.h>
#endif

#ifdef CONFIG_GCOV
extern void __gcov_dump(void);
#endif

#ifdef CONFIG_COGBT_DEBUG
extern uint64_t llvm_to_qemu;
extern uint64_t qemu_to_llvm;
extern uint64_t switch_context;
extern uint64_t tb_not_find;
extern uint64_t syscall_number;
#endif

void preexit_cleanup(CPUArchState *env, int code)
{
#ifdef CONFIG_GPROF
        _mcleanup();
#endif
#ifdef CONFIG_GCOV
        __gcov_dump();
#endif
#ifdef CONFIG_COGBT_DEBUG
        fprintf(stderr, "llvm_to_qemu = %ld, qemu_to_llvm = %ld\n", llvm_to_qemu, qemu_to_llvm);
        fprintf(stderr, "tb_not_find = %ld\n", tb_not_find);
        fprintf(stderr, "switch_context = %ld\n", switch_context);
        fprintf(stderr, "syscall_number = %ld\n", syscall_number);
#endif
        gdb_exit(code);
        qemu_plugin_user_exit();
}
