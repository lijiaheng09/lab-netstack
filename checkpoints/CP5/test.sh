set -x
C=$PWD
cd ../../utils/vnetUtils/examples
sudo ./makeVNetRaw <$C/vnet.txt
cd ../helper
for i in {1..6}; do
  sudo ./execNS ns$i ../../../build/tools/cli -f $C/scripts/ns$i-cli.txt >$C/outs/ns$i.out &
done
set +x
