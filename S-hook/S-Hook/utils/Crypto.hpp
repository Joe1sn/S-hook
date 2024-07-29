#pragma once

namespace Crypto {

    unsigned int cHash(const char str[], int len) {
        unsigned int hash = 0;
        size_t i = 0;
        for (i; i < len; i++)
        {
            hash = hash * 31 + str[i];
        }
        return hash;
    }

    unsigned int wHash(const wchar_t str[], int len) {
        unsigned int hash = 0;
        size_t i = 0;
        for (i; i < len; i++)
        {
            hash = hash * 31 + str[i];
        }
        return hash;
    }
}