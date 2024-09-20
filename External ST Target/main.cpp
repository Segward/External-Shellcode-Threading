#include <iostream>
#include <thread>
#include <chrono>

void func1(const char* a) {
    std::cout << a << std::endl;
}

void func2(int a) {
    std::cout << a << std::endl;
}

int func3(int a, int b) {
    int c = a + b;
    std::cout << c << std::endl;
    return c;
}

int main() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        func1("Hello, World!");
        func2(1);
        int c = func3(2, 3);
    }
    return 0;
}

