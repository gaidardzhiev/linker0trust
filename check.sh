#!/bin/sh

G='\033[0;32m'
R='\033[0;31m'
N='\033[0m'

ARCH=$(uname -m)

[ ! "$ARCH" = "x86_64" ] && { printf "unsupported architecture %s...\n" "$ARCH"; exit 1; }

[ ! -f linker ] && { make; printf "\n"; }

[ ! -f test.o ] && { make test; printf "\n"; }

fprint() {
	 printf "[%s] Test: %-20s Result: %b\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2"
}

fcheck() {	
	capture=$(./out.elf)
#	filtered=$(printf "%s" "$capture" | grep -i '>>> !!! payload executed !!! <<<')
	expected=">>> !!! linker payload executed !!! <<<
Should I trust the linker?"
	[ "$capture" = "$expected" ] && {
		fprint "Injection Test" "${G}PASSED${N}";
		return 0;
	} || {
		fprint "Injection Test" "${R}FAILED${N}";
		return 	32;
	}
}

{ fcheck; return="$?"; } || exit 1

[ "$return" -eq 0 ] 2>/dev/null || printf "%s\n" "$return"
