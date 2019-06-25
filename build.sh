#! /bin/bash
read -t 5 -p "请输入编译类型（ARM输入 1；X86输入 2；X64输入 3）: " default_Compiler_environment

if [ $default_Compiler_environment == 1 ]
then 
	echo "Compiler_environment : ARM"
	source /opt/fsl-imx-fb/4.9.88-2.0.0/environment-setup-cortexa9hf-neon-poky-linux-gnueabi
	cp ./lib/libarm/* ./lib	
elif [ $default_Compiler_environment == 2 ]
then
	echo "Compiler_environment : X86"
	cp ./lib/lib32/* ./lib	
elif [ $default_Compiler_environment == 3 ]
then
	echo "Compiler_environment : X64"
	cp ./lib/lib64/* ./lib	
fi

mkdir build

cd build

cmake ..

make clean

make 

cd ..
