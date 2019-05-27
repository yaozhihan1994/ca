//asn1c 0.9.28
asn1c -gen-PER -fincludes-quoted Common2.asn

//build
source /opt/fsl-imx-fb/4.9.88-2.0.0/environment-setup-cortexa9hf-neon-poky-linux-gnueabi
sh build.sh

//run (it will mkdir, if "dirs" not exists)
./server



