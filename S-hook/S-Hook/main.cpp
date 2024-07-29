// S-Hook.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "S-Hook.h"

// 定义指向原始 test 函数的指针类型
typedef void (WINAPI* Test_t)();

Test_t oldTestptr = nullptr;

void test() {
    int i = 1;
    ++i;
    ++i;
    --i;
    i--;
    std::cout << "test\n";
}

void test2() {
    int i = 1;
    ++i;
    ++i;
    --i;
    i--;
    std::cout << "hooked test\nnow use old addr\n";
    oldTestptr();
}

int main()
{
    SHook::createHook("test", test, test2, reinterpret_cast<LPVOID*>(&oldTestptr));
    SHook::enableHook("test");
    test();
    SHook::disableHook("test");
    test();
    return 0;
}