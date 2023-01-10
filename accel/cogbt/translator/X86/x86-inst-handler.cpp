#include "x86-inst-handler.h"

/* const char X86InstHandler::PFTable[256] = { */
/*     4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4, 0, 4, 4, 0, 4, 0, */
/*     0, 4, 4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, */
/*     0, 4, 4, 0, 4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4, */

/*     0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0, 4, 0, 0, 4, 0, 4, */
/*     4, 0, 0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, */
/*     4, 0, 0, 4, 0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0, */

/*     0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0, 4, 0, 0, 4, 0, 4, */
/*     4, 0, 0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, */
/*     4, 0, 0, 4, 0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0, */

/*     4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4, 0, 4, 4, 0, 4, 0, */
/*     0, 4, 4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, */
/*     0, 4, 4, 0, 4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4, */
/* }; */

bool X86InstHandler::CFisDefined() {
    return Inst->detail->x86.eflags &
           (X86_EFLAGS_RESET_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_MODIFY_CF);
}

bool X86InstHandler::OFisDefined() {
    return Inst->detail->x86.eflags &
           (X86_EFLAGS_RESET_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_MODIFY_OF);
}

bool X86InstHandler::ZFisDefined() {
    return Inst->detail->x86.eflags &
           (X86_EFLAGS_RESET_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_MODIFY_ZF);
}

bool X86InstHandler::SFisDefined() {
    return Inst->detail->x86.eflags &
           (X86_EFLAGS_RESET_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_MODIFY_SF);
}

bool X86InstHandler::PFisDefined() {
    return Inst->detail->x86.eflags &
           (X86_EFLAGS_RESET_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_MODIFY_PF);
}

bool X86InstHandler::AFisDefined() {
    return Inst->detail->x86.eflags &
           (X86_EFLAGS_RESET_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_MODIFY_AF);
}
