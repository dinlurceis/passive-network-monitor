#include <gtest/gtest.h>
#include "parsers/http_parser.hpp"
#include <cstring>

static const char* HTTP_REQUEST_WINDOWS =
    "GET /index.html HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
    "Accept: */*\r\n"
    "\r\n";

static const char* HTTP_REQUEST_ANDROID =
    "GET / HTTP/1.1\r\n"
    "User-Agent: Mozilla/5.0 (Linux; Android 12; Pixel 6) Mobile Safari/537.36\r\n"
    "\r\n";

static const char* HTTP_REQUEST_NO_UA =
    "GET / HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "\r\n";

static const char* HTTP_RESPONSE =
    "HTTP/1.1 200 OK\r\n"
    "User-Agent: ShouldNotMatch\r\n"
    "\r\n";

TEST(HttpParser, ExtractWindowsUA) {
    auto ua = pnads::extract_user_agent(
        reinterpret_cast<const uint8_t*>(HTTP_REQUEST_WINDOWS),
        std::strlen(HTTP_REQUEST_WINDOWS));
    ASSERT_TRUE(ua.has_value());
    EXPECT_NE(ua->find("Windows NT"), std::string::npos);
}

TEST(HttpParser, ExtractAndroidUA) {
    auto ua = pnads::extract_user_agent(
        reinterpret_cast<const uint8_t*>(HTTP_REQUEST_ANDROID),
        std::strlen(HTTP_REQUEST_ANDROID));
    ASSERT_TRUE(ua.has_value());
    EXPECT_NE(ua->find("Android"), std::string::npos);
}

TEST(HttpParser, NoUAReturnsNullopt) {
    auto ua = pnads::extract_user_agent(
        reinterpret_cast<const uint8_t*>(HTTP_REQUEST_NO_UA),
        std::strlen(HTTP_REQUEST_NO_UA));
    EXPECT_FALSE(ua.has_value());
}

TEST(HttpParser, ResponseIgnored) {
    // HTTP responses should not be parsed (only requests)
    auto ua = pnads::extract_user_agent(
        reinterpret_cast<const uint8_t*>(HTTP_RESPONSE),
        std::strlen(HTTP_RESPONSE));
    EXPECT_FALSE(ua.has_value());
}

TEST(HttpParser, EmptyReturnsNullopt) {
    auto ua = pnads::extract_user_agent(nullptr, 0);
    EXPECT_FALSE(ua.has_value());
}
