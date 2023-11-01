#!/bin/sh
export CFLAGS="-Wno-error=unused-but-set-variable -Wno-error=unused-function"
make_configure=0

help() {
    echo "Usage:"
    echo "  -c              configure"
    echo "  -h              help"
}

parseArgs() {
    while getopts "ch" opt; do
        case ${opt} in
        c)
            make_configure=1
            ;;
        h)
            help
            exit
            ;;
        # 若选项需要参数但未收到，则走冒号分支
        :)
            help
            exit
            ;;
        # 若遇到未指定的选项，会走问号分支
        ?)
            help
            exit
            ;;
        esac
    done
}

make_cmd() {
    cd $(dirname $0)/../
    mkdir -p build64-qemu
    cd build64-qemu

    if [ $make_configure -eq 1 ] ; then
        ../configure --target-list=x86_64-linux-user \
        --extra-ldflags=-lcapstone
    fi

    if [ ! -f "/usr/bin/ninja" ]; then
        make -j $(nproc)
    else
        ninja
    fi
}

parseArgs "$@"
make_cmd
