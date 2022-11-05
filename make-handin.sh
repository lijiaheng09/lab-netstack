LAB=2

SUF=`cat handin-suf.txt`
mkdir -p .tmp/lab"$LAB"
cp -r src/ CMakeLists.txt report/README.pdf report/not-implemented.pdf checkpoints/ utils/ .tmp/lab"$LAB"
tar -cf lab"$LAB"-"$SUF".tar -C .tmp lab"$LAB"
rm -r .tmp/
