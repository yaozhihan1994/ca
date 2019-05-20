#ifndef A_H_
#define A_H_
namespace AA{
extern int a;
}
class T{
public:
int a;

template<class T> static std::string ToString(const T& t);
};
#endif
