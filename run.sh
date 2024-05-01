set -e

# cd ~/cogbt-home/cogbt-20240113

# compile
# rm ./build64-dbg -rf; cd build-shell; bash build64-dbg.sh -c; cd ..
# 有时候修改了文件，但是不会重新编译，原因不明，所以手动删除
rm -f build64-dbg/libqemu-x86_64-linux-user.fa.p/accel_cogbt_translator_X86_x86-fpu.cpp.o
# rm build64-dbg/libqemu-x86_64-linux-user.fa.p/accel_cogbt_translator_X86_x86-translator.cpp.o
# rm ./build64-dbg/libqemu-x86_64-linux-user.fa.p/target_i386_tcg_fpu_helper.c.o
cd build-shell; bash build64-dbg.sh; cd ..


# run dbt test
# ./build64-dbg/qemu-x86_64 $1
./test.out
# COGBT_DEBUG_MODE=guest_ins,host_ins ./build64-dbg/qemu-x86_64 --singlestep test.out 2>test.debug.log
# ./build64-dbg/qemu-x86_64 --singlestep -d cpu,fpu,nochain test.out 2>test.cogbt.log
./build64-dbg/qemu-x86_64 ../dbt5_ut/fldst/fist
