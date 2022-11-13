if [ $# -ne 2 ]; then
	echo "Usage: $1 <device> <add/del>" >/dev/stderr
	exit
fi
tc qdisc $2 dev $1 root netem delay 100ms 50ms loss random 10% corrupt 10% duplicate 10% reorder 10%
