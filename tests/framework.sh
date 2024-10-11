# Framework for testing
#
# This must be sourced by a test script

# Paths to our tools. They can be overridden from the caller's
# environment.
TOP_DIR=$(realpath $(pwd)/../..)
VIRTME_DIR=${VIRTME_DIR:-$TOP_DIR/virtme}
QEMU_DIR=${QEMU_DIR:-$TOP_DIR/cassini-qemu/x86_64-softmmu}

# An error was found. Dump the script stack, and display the message
# in the argument, and exit.
function error {
    echo "Error at:"
    local frame=0
    while caller $frame; do
        ((frame++));
    done

    echo $1

    exit 1
}

# Start a VM, load the test driver, and exits
# arg 1 = the script to run
function startvm {
    export PATH=$QEMU_DIR:$VIRTME_DIR:/sbin:$PATH

    # -M q35 = Standard PC (Q35 + ICH9, 2009) (alias of pc-q35-2.10)
    QEMU_OPTS="--qemu-opts -device ccn -machine q35,kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on -m 2G"
    KERN_OPTS="--kopt iommu=pt --kopt intel_iommu=on --kopt iomem=relaxed"
    VIRTME_OPTS="--rodir=/lib/firmware=${TOP_DIR}/hms-artifacts"
    if [[ -v KDIR ]]; then
	KERNEL="--kdir $KDIR --mods=auto"
    else
	KERNEL="--installed-kernel"
    fi

    mkdir -p $(pwd)/tmptests
    echo "virtme-run $KERNEL --pwd --rwdir=$(pwd)/tmptests " \
         "--script-sh $1 $VIRTME_OPTS $KERN_OPTS $QEMU_OPTS" > test_cmd.sh
    chmod +x test_cmd.sh
    ../../nic-emu/netsim ./test_cmd.sh
}

# Returns the log name for the output
# ie. if the script is called test1.sh, the output is test1.log
# arg 1: an optional suffix
# Output sample: basic1.log         (without an argument)
# Output sample: basic1-foo.log     (with foo as an argument)
function log {
    local suffix

    if [ -z "$1" ]; then
        suffix=""
    else
        suffix="-$1"
    fi

    echo $(basename $0 .sh)$suffix.log
}

# Count the number of regex occurrence in one or more files and bail
# out if the count is not right
# arg 1 = count
# arg 2 = grep regex
# arg 3 = filename(s)
function ecount()
{
    local C=$(egrep "$2" ${@:3} | wc -l)

    [ $C -eq $1 ] || error "counted $C, expected $1 for \"$2\" in ${@:3}"
}
