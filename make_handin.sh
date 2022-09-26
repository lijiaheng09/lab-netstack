LAB=1

SUF=`cat handin_suf.txt`
mkdir -p .tmp/lab"$LAB"
cp -r src/ CMakeLists.txt report/README.pdf report/not-implemented.pdf checkpoints/ .tmp/lab"$LAB"
tar -cf lab"$LAB"-"$SUF".tar -C .tmp lab"$LAB"
rm -r .tmp/
