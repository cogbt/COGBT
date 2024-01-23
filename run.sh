set -e


cd buildqemu
ninja
cd ..
./buildqemu/qemu-x86_64 e1.out #2> e1.out.pathd
sort e1.out.path -o e1.out.path
cd build
ninja
cd ..
echo $(head -n +1 e1.out.path | cut -d x -f 2).o
COGBT_DEBUG_MODE=$1 ./build/qemu-x86_64 -m tb_aot e1.out
echo "======= TEST BEGIN ======="
# ./build/qemu-x86_64 -a $(head -n +1 e1.out.path | cut -d x -f 2).o e1.out
./build/qemu-x86_64 -a e1.out.aot e1.out
echo "======= TEST END ========="
