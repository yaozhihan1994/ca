asn1c 版本 0.9.28或者0.9.29
asn 编译命令： asn1c -gen-PER -fincludes-quoted Common2.asn

程序编译
1. 执行./clean.sh 删除build文件夹
2. 修改 build.sh 文件的第7行 default_Compiler_environment=$ARM 修改ARM为X64或者X86
	build.sh 执行时会到lib文件夹下根据设置的编译选项 拷贝lib32 或lib64 或libarm文件夹下的库文件到 lib文件夹下
	程序编译时链接lib文件夹下的库
3. 执行./build.sh  会创建build文件夹，编译好的程序会保存在output文件夹下 名字是server
	output文件夹下的32 64 arm文件夹里是已经编译好的程序
	
程序运行
1. export LD_LIBRARY_PATH=/opt/NL/CA/lib/
2. 执行 nice -19 /opt/NL/CA/bin/server > /dev/null &
	后台运行程序，注意执行完命令不可以直接关闭命令行窗口，需要用 exit 命令退出窗口
	
程序执行流程
1. 程序初始化ca证书，首先会检测ca文件夹下以下文件是否存在：
	rootca.crt		rootca.key
	subrootca.crt	subrootca.key
	eca.crt			eca.key
	pca.crt			pca.key
	rca.crt			rca.key
	cca.crt			cca.key
	全部存在的话 将ca的key,hashid8,uper编码后的buffer等存为全局变量（CertOp里的s_CaInfo结构体）
	有一个不存在，就会创建新的CA（6个ca都重建）
	
	重建CA：检测以下文件夹和文件是否存在，不存在就创建
	crls //存放crl列表的文件夹
	pcrts //存放假名证书的文件夹 假名证书池
	rcrts //存放道路证书的文件夹 道路证书池
	ca	//存放ca证书和key的文件夹
	serial_number //存放crl序列号和设备序列号的文件夹
	serial_number/crl_serial_number //crl的序列号，每次程序开始时会读入序列号，每次生成新的crl会将新的序列号写入文件
	serial_number/device_serial_number //crl的序列号，每次程序开始时会读入
	
	重建后将ca的key,hashid8,uper编码后的buffer等存为全局变量（CertOp里的s_CaInfo结构体）
	
	ca证书的存储形式是 证书的uper编码， ca公私钥的存储形式是 先私钥32字节 在公钥64字节，这里的公私钥是用BN_bn2bin转换后的16进制数
	假名证书池pcrts文件夹和道路证书池rcrts文件夹中证书的存储形式是 先32字节的私钥，在接uper证书编码
	crls文件夹中crl的存储形式为crl的uper编码
	
2. 程序初始化证书池，crl列表
	分别用2个list存证书池中的证书的文件名，文件名格式为“证书过期时间_证书序号”
	用map存crls文件夹里的crl,key是文件名，文件名格式为“证书过期时间_证书序号” value是crl中被撤销证书的hashid10
	
3. 程序初始化结束后，开3个线程管理假名证书池和道路证书池以及crl列表
	假名/道路证书池管理：	循环检测证书池中证书个数是否小于设定值 若小于则新建证书放入list中，每日晚上2点检测list中证书是否过期，若过期则删除
	crl管理：	每日晚2点检测crl列表的map中每个crl是否过期，过期则删除

4. 程序主线程处理通信请求
	首先创建socket 监听端口6666，bind 并 listen
	循环accpet连接，每接收一个链接就开一个线程处理这个连接，用互斥锁和条件变量控制连接的最大并发数
	在每个处理连接的线程中循环接受消息并处理，设置接收消息的超时时间，若超时未收到消息则关闭连接、结束线程。
	对于接收到的消息按照协议解析获取数据，对不同的标识位cmd调用不同的处理函数deal_with_c0/c1/c2/c3/c4/c5/c6....


