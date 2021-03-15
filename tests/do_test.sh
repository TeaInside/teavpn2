#!/bin/sh

GREEN="32"
BOLDGREEN="\e[1;${GREEN}m"
ENDCOLOR="\e[0m"

for i in ${@}; do
	/bin/echo -e "${BOLDGREEN}[Testing] $i${ENDCOLOR}";
	# $VG $VGFLAGS --log-file="$i.log" "$i";
	$i;
done;
