#include "sha256.h"
#include "gtest/gtest.h"

TEST(SHA256, Hash_Test) {
SHA256 sha256{};
std::string message = "The quick brown fox jumps over the lazy dog";
std::string expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
std::string output = sha256.Hash(message);
EXPECT_EQ(expected,output);
}

TEST(SHA256, Hash_Test_lavina) {
  SHA256 sha256{};
  std::string message = "The quick brown fox jumps over the lazy cog";
  std::string expected = "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be";
  std::string output = sha256.Hash(message);
  EXPECT_EQ(expected,output);
}

TEST(SHA256, Hash_Test_empty) {
  SHA256 sha256{};
  std::string message = "";
  std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  std::string output = sha256.Hash(message);
  EXPECT_EQ(expected,output);
}