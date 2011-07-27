#!/bin/sh


echo "lconv"

cd ../

lcov --directory tests --zerocounters

make check

lcov --directory ./ --capture --output-file check.info
mkdir -p doc/html/lcov
genhtml -o doc/html/lcov check.info 

# genhtml check.info 

cd doc

echo "doxygen"

doxygen doxygen.conf

