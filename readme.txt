//asn1c version 0.9.28
asn1c -gen-PER -fincludes-quoted Common2.asn

//build
modify build.sh
change default_Compiler_environment (ARM, X86, X64)
./clean.sh
./build.sh
server is in build/output/


//run 
./server



