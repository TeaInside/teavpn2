#!/bin/sh

for i in ${@}; do
	echo "[Testing] $i";
	echo $LD_PRELOAD;
	echo $VG $VGFLAGS --log-file="$i.log" "$i";
	$VG $VGFLAGS --log-file="$i.log" "$i";
done;
