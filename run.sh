set -e

# cd ~/cogbt-home/cogbt-20240113

# compile
# rm ./build64-dbg -rf; cd build-shell; bash build64-dbg.sh -c; cd ..
cd build-shell; bash build64-dbg.sh; cd ..


# run dbt test
./build64-dbg/qemu-x86_64 $1
