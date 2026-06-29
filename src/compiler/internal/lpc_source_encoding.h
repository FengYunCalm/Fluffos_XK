#ifndef LPC_SOURCE_ENCODING_H
#define LPC_SOURCE_ENCODING_H

#include "compiler/internal/LexStream.h"

#include <memory>
#include <string>

struct LpcSourceEncodingResult {
  std::string encoding{"utf-8"};
  bool transcoded{false};
  int invalid_sequence_count{0};
  std::string data;
  std::string error;
};

LpcSourceEncodingResult lpc_source_decode_to_utf8(const std::string &source);
std::unique_ptr<LexStream> lpc_source_encoding_stream(std::unique_ptr<LexStream> source);

#endif /* LPC_SOURCE_ENCODING_H */
