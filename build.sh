#! /bin/bash

ARM="ARM"
X86="X86"
X64="X64"

default_Compiler_environment=$X86

if [ $default_Compiler_environment == $ARM ]
then 
	echo "Compiler_environment : ARM"
	source /opt/fsl-imx-fb/4.9.88-2.0.0/environment-setup-cortexa9hf-neon-poky-linux-gnueabi
	cp ./lib/libarm/* ./lib	
elif [ $default_Compiler_environment == $X86 ]
then
	echo "Compiler_environment : X86"
	cp ./lib/lib32/* ./lib	
elif [ $default_Compiler_environment == $X64 ]
then
	echo "Compiler_environment : X64"
	cp ./lib/lib64/* ./lib	
fi

cmake ./build/CMakeLists.txt
make -C ./build/
