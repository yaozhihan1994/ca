#! /bin/bash

if test -e ./output/server
then
	rm ./output/server
fi

if test -d ./build/CMakeFiles
then
	rm -rf ./build/CMakeFiles
fi

if test -e ./build/CMakeCache.txt
then
	rm ./build/CMakeCache.txt
fi

if test -e ./build/cmake_install.cmake
then
	rm ./build/cmake_install.cmake
fi

if test -e ./build/Makefile
then
	rm ./build/Makefile
fi
