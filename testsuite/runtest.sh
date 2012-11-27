#! /bin/bash

declare -r ENCODERS=$1
declare -r DECODERS=$2
declare -r INFILES=$3
declare -r ENCODEOPTS=$4
declare -r DECODEOPTS=$5

VALGRIND=(
  valgrind -q --tool=memcheck 
  --error-exitcode=66 --read-var-info=yes 
)

STRACE=( strace -f )
LTRACE=( ltrace -f )

: ${FIRST_ID:=0}
: ${RUN_VALGRIND:=true}
: ${RUN_STRACE:=false}
: ${RUN_LTRACE:=false}
: ${KEEP_BROKEN:=false}

start() {
    printf "[%3u] %s..." "$id" "$*"
}

ok() {
    printf " ${1-[ok]\n}"
}

_exp_fail() {
    test $1 -ne 0 || {
      echo "Program succeeded unexpectedly" >&2
      return 1
    }
}

_exp_ignore() {
    return 0
}

_exp_success() {
    test $1 -eq 0
}

_exec() {
    local prog=$1
    local rc=0
    local fn

    shift
    case $prog in
      -*)	prog=${prog##-}; SKIP_POST=true; fn=_exp_fail ;;
      ~*)	prog=${prog##~}; SKIP_POST=true; fn=_exp_ignore ;;
      !*)	prog=${prog##!}; GREMLIN=true;   fn=_exp_success ;;
      *)	fn=_exp_success ;;
    esac

    set -- "${W[@]}" "$prog" "$@"

    set +e
    if test -n "$STDIN"; then
	cat "$STDIN" | "$@" 2>$tmpdir/.err
    else
	"$@" 2>$tmpdir/.err
    fi
    r=$?
    set -e

    $IGNORE_RET || $fn $r || rc=1

    test $rc -eq 0 || \
	cat $tmpdir/.err >&2

    return $rc
}

id=${BASE_ID:-0}
runit() {
    echo "[$id] $@" >> $tmpdir/cmd

    local failed=false
    local W
    local IGNORE_RET

    if $RUN_STRACE; then
	W=( "${STRACE[@]}" -o $tmpdir/strace.$id )
	IGNORE_RET=true
	_exec "$@" >/dev/null
	ok "[strace]"
    fi

    if $RUN_LTRACE; then
	W=( "${LTRACE[@]}" -o $tmpdir/ltrace.$id )
	IGNORE_RET=true
	_exec "$@" >/dev/null
	ok "[ltrace]"
    fi

    if $RUN_VALGRIND; then
	W=( "${VALGRIND[@]}" )
	IGNORE_RET=false
	_exec  "$@" >/dev/null
	ok "[valgrind]"
    fi

    W=( )
    IGNORE_RET=false
    _exec "$@" >&3

    let ++id
}

cleanup() {
    $KEEP_BROKEN || rm -rf $tmpdir
}

test "$id" -ge "$FIRST_ID" || exit 0

tmpdir=`mktemp -t -d stream-test.XXXXXX` || exit 1
trap "cleanup" EXIT

set -e

export O=$tmpdir/
for encoder in $ENCODERS; do
    for infile in $INFILES; do
	rm -f "$tmpdir"/*

	STDIN=
	GREMLIN=false
	start "Creating stream of '$infile' with '$encoder'"
	runit $encoder -h "$ENCODEOPTS"=$infile 3> $tmpdir/stream
	ok

	! $GREMLIN || bin/gremlin $tmpdir/stream

	STDIN=$tmpdir/stream
	for decoder in $DECODERS; do
	    SKIP_POST=false

	    start "  Processing with '$decoder'" 
	    runit $decoder $DECODEOPTS --execute "`pwd`/nullcat" 3>&1
	    ok

	    ! $SKIP_POST || continue

	    test -e $tmpdir/start -a -e $tmpdir/end -a \
		-e $tmpdir/result -a ! -e $tmpdir/result.tmp || {
	      echo "Bad result:" 
	      ls -l $tmpdir/
	      false
	    } >&2

	    cmp $tmpdir/result $infile || {
	      echo "Mismatch"
	      ls -l $tmpdir/
	      false
	    } >&2

	done
    done
done

KEEP_BROKEN=false
