#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include <thread>
#include <mutex>
#include <list>
using namespace std;
/*
class test{
public:
	 template<class T> static string ToString(const T& t){
	    ostringstream oss;  
	    oss<<t;            
	    return oss.str();   
	}
};
void test(unsigned char* a, int b){
for(int i = 0; i< b; i++){
  printf("0x%02x ",*(a+i));
}
cout<<endl;
}
*/
mutex m;
void test2(char a[], int b, int c){
	lock_guard<mutex> lck(m);
	printf("0x%02x\n",a[0]);
	printf("0x%02x\n",a[1]);
	sleep(2);
}

unsigned char* IntToUnsignedChar(unsigned int num){
    unsigned char *ret = (unsigned char* )malloc(4);
    if (!ret) {
        printf("IntToUnsignedChar malloc fail\n");
        return NULL;
    }
    ret[0] = num >> 24;
    ret[1] = num >> 16;
    ret[2] = num >> 8;
    ret[3] = num;
    return ret;
}
int main(){
/*
list<string> l;
l.push_back("a");
l.push_back("b");
l.push_back("c");
for (std::list<string>::iterator i = l.begin(); i != l.end(); i++) {
	cout<<*i<<endl;

}



cout<<test::ToString(6)<<endl;
string s("aa");

s= "sda" + s;
cout<<s<<endl;
unsigned char a[5] = {};
test(a, 5);
mutex m;
lock_guard<mutex> lock(m);

err:{

}
*/
unsigned char 


getchar();
return 0;
}
