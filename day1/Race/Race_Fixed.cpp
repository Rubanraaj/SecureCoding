#include <iostream>
#include <thread>
#include <mutex>

int counter = 0;
std::mutex mutex;

void increment() {
    for (int i = 0; i < 1000000; ++i) {
        std::lock_guard<std::mutex> lock(mutex);
        ++counter;
    }
}

int main() {
    std::thread t1(increment);
    std::thread t2(increment);

    t1.join();
    t2.join();

    std::cout << "Counter: " << counter << std::endl;
    return 0;
}

/* g++ race.cpp -o race -pthread */