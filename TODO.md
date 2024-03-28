## 已翻译指令

- fld，80 位部分暂用 helper
- fstp，80 位部分暂用 helper
- fucomi，部分暂用 helper，涉及 fpus
- fucomip，部分暂用 helper，涉及 fpus
- fldz
- fldl2e
- fsubp
- fild
- fdecstp
- fld1
- fldpi
- fldln2
- fldlg2
- fldl2t
- fincstp
- fst
- fist
- fistp
- fsubp
- fisub
- fsub
- fsubr
- fxch
- fabs
- fchs
- f2xm1
- fadd
- fiadd
- faddp
- fadd
- fiadd
- faddp
- fisubr
- fsubrp
- fcmovbe
- fcmovb
- fcmove
- fcmovnbe
- fcmovnb
- fcmovne
- fcmovnu
- fcmovu
- fcos
- fsin
- fsqrt
- fatan，部分暂用 helper，太过复杂
- fptan，部分暂用 helper，涉及 fpush/pop
- fsincos，部分暂用 helper，涉及 fpush/pop
- fprem，部分暂用 helper，太过复杂，涉及 fpus
- fprem1，部分暂用 helper，太过复杂，涉及 fpus
- fcomp，部分暂用 helper，涉及 fpus
- fcompp，部分暂用 helper，涉及 fpus
- fcom，部分暂用 helper，涉及 fpus
- fcomi，部分暂用 helper，涉及 fpus
- fcomip，部分暂用 helper，涉及 fpus
- fldcw，部分暂用 helper，涉及 fpus
- fstcw，部分暂用 helper，涉及 fpus
- fdiv
- fidiv
- fdivp
- fdivr
- fidivr
- fidivrp
- ficom，部分暂用 helper，涉及 fpus
- ficomp，部分暂用 helper，涉及 fpus
- wait，暂用 helper
- fmul
- fmulp
- fimul
- fscale，测例有问题，空函数也可以通过；未判断输入合法性
- frndint
- ftst，已实现但存在问题，未启用
- fxtract，部分暂用 helper，太过复杂，涉及 fpush/pop
- fyl2x，未判断输入合法性
- fyl2xp1，未判断输入合法性

## 测例

- [ ] fldst
  - [x] fild
  - [x] fist
  - [x] fistp
  - [x] fld
  - [x] fld1
  - [x] fldcw-fnstcw
  - [x] fldcw-fstcw
  - [ ] fnstsw
  - [x] fst
  - [x] fstp
  - [ ] fstsw
  - [x] fsub
  - [x] fxch
- [ ] farith
  - [x] f2xm1
  - [x] fabs
  - [x] fadd
  - [x] fchs
  - [x] fcmovb
  - [x] fcmovbe
  - [x] fcmove
  - [x] fcmovnb
  - [x] fcmovnbe
  - [x] fcmovne
  - [x] fcmovnu
  - [x] fcmovu
  - [x] fcom
  - [x] fcomi，x86 可完全通过，helper 版本和本版本均只可通过一半
  - [x] fcos
  - [x] fdiv
  - [x] fdivr
  - [x] ficom，x86 可通过 1 个，helper 版本和本版本均只可通过 7 个
  - [x] fincstp
  - [x] fmul
  - [x] fpatan
  - [x] fprem
  - [x] fprem1
  - [x] fptan
  - [x] frndint
  - [x] fscale
  - [x] fsin
  - [x] fsincos
  - [x] fsqrt
  - [x] fsub
  - [x] fsubp
  - [x] fsubr
  - [x] ftst，x86 可通过 1 个，helper 版本可通过全部 152 个，本版本可通过 19 个
  - [x] fxtract
  - [x] fyl2xp1
- [ ] fctrl
  - [ ] ffree
  - [ ] fincstp-fdecstp
  - [ ] finit
  - [ ] fldenv-fnstenv
  - [x] fldlx
  - [ ] fnclex
  - [ ] fninit
  - [ ] fnsave