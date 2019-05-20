#include<iostream>
#include<thread>
#include<mutex>
#include<condition_variable>
#include<unistd.h>
class Semaphore {
public:
  Semaphore(unsigned int count = 1)
    : count_(count) {
  }
 
  void Signal() {
{
    std::lock_guard<std::mutex> lck(mutex_);
    	count_++;
}
cv_.notify_one();
	
	
  }
 
  void Wait() {
    std::unique_lock<std::mutex> lck(mutex_);
	std::cout << count_ << std::endl;
	while(count_ == 0){
	    cv_.wait(lck);
	}
	count_--;
  }
 
private:
  std::mutex mutex_;
  std::condition_variable cv_;
  unsigned int count_;
};

Semaphore g_semaphore(10);

void Worker(int i){
  std::cout << "Thread " << i << ": wait succeeded" << std::endl;
  // Sleep 1 second to simulate data processing.
  sleep(rand()%10);
  g_semaphore.Signal();
}

int main() {
int i = 1;

while(true){
  g_semaphore.Wait();
  std::thread t(Worker, i);
  t.detach();
  i++;
  usleep(1);

}
  getchar();
  return 0;
}
