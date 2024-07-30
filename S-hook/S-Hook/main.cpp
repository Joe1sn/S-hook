// S-Hook.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "S-Hook.h"

// 定义指向原始 test 函数的指针类型
typedef void (WINAPI* Test_t)();
typedef void (WINAPI* Sleep_t)(DWORD);

Test_t oldTestptr = nullptr;
Sleep_t oldSleep = nullptr;

void test() {
    puts("test first line\n");
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

void WINAPI MySleep(DWORD mil) {
    std::cout << "mil: " << mil << std::endl;
    oldSleep(mil);
}
int main()
{
    SHook::createHook("test", test, test2, reinterpret_cast<LPVOID*>(&oldTestptr));
    SHook::enableHook("test");
    test();
    SHook::disableHook("test");
    test();

    //SHook::createHook("Sleep", Sleep, MySleep, reinterpret_cast<LPVOID*>(&oldSleep));
    //Sleep(1021);
    //SHook::enableHook("Sleep");
    //Sleep(1021);
    return 0;
}