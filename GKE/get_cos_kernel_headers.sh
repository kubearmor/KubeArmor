#!/bin/bash

for VERSION in $(gsutil ls gs://cos-tools/ | grep -v scripts | awk -F'/' '{print $4}')
do
	echo "COS-VERSION: $VERSION"
	gsutil ls gs://cos-tools/$VERSION/kernel-headers.tgz 2> /dev/null
	if [ $? == 0 ]; then
		if [ ! -f "cos/$VERSION/kernel-headers.tgz" ]; then
			mkdir -p cos/$VERSION
			gsutil cp gs://cos-tools/$VERSION/kernel-headers.tgz cos/$VERSION/
		fi
	fi
done
