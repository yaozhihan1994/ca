#include "a.h"
#include <iostream>
#include <sstream>

int a = 5;
using namespace std;
template<class T> string T::ToString(const T& t){
    ostringstream oss;  
    oss<<t;            
    return oss.str();   
}
