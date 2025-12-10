#include <UnitTest++/UnitTest++.h>
#include "code.h"
#include <string>

std::string s = "HELLO";

SUITE(KeyTest) {
    TEST(ValidKey) {
        code cipher(3, "HELLO");
        CHECK_EQUAL("LEHLO", cipher.encryption(s));
    }
    TEST(LongKey) {
        CHECK_THROW(code(1, "HELLO"), cipher_error);
    }
}

struct KeyB_fixture {
    code * t;
    KeyB_fixture() {
        t = new code(3, "HELLO");
    }
    ~KeyB_fixture() {
        delete t;
    }
};

SUITE(EncryptTest) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::string input = "HELLO";
        CHECK_EQUAL("LEHLO", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::string input = "hello";
        CHECK_EQUAL("lehlo", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        std::string input = "HELLO WORLD";
        CHECK_EQUAL("LWLEORHLOD", t->encryption(input));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        std::string input = "HELL6";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        std::string input = "";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        std::string input = "1234+8765=9999?";
        CHECK_THROW(t->encryption(input), cipher_error);
    }
    TEST(MaxShiftKey) {
        code cipher(8, "ABCDEFGH");
        std::string input1 = "HGFEDCBA";
        std::string input2 = "ABCDEFGH";
        CHECK_THROW(cipher.transcript(input1, input2), cipher_error);
    }
}

SUITE(DecryptText) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::string input1 = "LHLOE";
        std::string input2 = "HELLO";
        CHECK_EQUAL("LHLOE", t->transcript(input1, input2));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::string input1 = "lhloe";
        std::string input2 = "hello";
        CHECK_EQUAL("lhloe", t->transcript(input1, input2));
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        std::string input1 = "HELLOWORLD";
        std::string input2 = "HELLO WORLD";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        std::string input1 = "HELL6";
        std::string input2 = "HELL6";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        std::string input1 = "HELLO!";
        std::string input2 = "HELLO!";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        std::string input1 = "";
        std::string input2 = "";
        CHECK_THROW(t->transcript(input1, input2), cipher_error);
    }
    TEST(MaxShiftKey) {
        code cipher(8, "Serafime");
        std::string input1 = "HGFEDCBA";
        std::string input2 = "ABCDEFGH";
        CHECK_THROW(cipher.transcript(input1, input2), cipher_error);
    }
}

int main(int argc, char **argv) {
    return UnitTest::RunAllTests();
}