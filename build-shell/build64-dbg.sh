#!/bin/sh
export CFLAGS="-Wno-error=unused-but-set-variable -Wno-error=unused-function"
make_configure=0
opt_level=1
LLVM_HOME=$LLVM_HOME

help() {
    echo "Usage:"
    echo "  -c              configure"
    echo "  -O              [options]"
    echo "                  default: -O 1"
    echo "                  -O 0 : Disable all optimization, include jmp_cache, custom_pass_optimization"
    echo "                  -O 1 : Open stable optimization"
	echo "  -l				[LLVM_HOME]"
	echo "					default: using environment variables: LLVM_HOME"
    echo "  -h              help"
}

parseArgs() {
    while getopts "cO:l:h" opt; do
        case ${opt} in
        c)
            make_configure=1
            ;;
        O)
            opt_level="$OPTARG"
            ;;
		l)
			LLVM_HOME="$OPTARG"
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
    mkdir -p build64-dbg
    cd build64-dbg

    if [ $make_configure -eq 1 ] ; then
		if [ -z $LLVM_HOME ] ; then
			echo "using -l option or set environment variables LLVM_HOME"
			exit
		fi

		if [ "$opt_level" = "0" ] ; then
			../configure --target-list=x86_64-linux-user --llvm-home=$LLVM_HOME \
				--enable-cogbt --enable-debug --enable-cogbt-debug \
				--disable-custom-pass-optimization \
				--extra-ldflags=-lcapstone
		elif [ "$opt_level" = "1" ] ; then
			../configure --target-list=x86_64-linux-user --llvm-home=$LLVM_HOME \
				--enable-cogbt --enable-debug --enable-cogbt-debug \
				--enable-cogbt-jmp-cache \
				--extra-ldflags=-lcapstone
		else
			echo "invalid options"
            exit
		fi
    fi

    if [ ! -f "/usr/bin/ninja" ]; then
        make -j $(nproc)
    else
        ninja
    fi
}

parseArgs "$@"
make_cmd
