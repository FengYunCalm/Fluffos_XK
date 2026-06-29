#include "compiler/internal/lpc_source_encoding.h"

#include "compiler/internal/lpc_modern_profile.h"

#include <unicode/ucnv.h>

#include <cstring>
#include <utility>

namespace {
class OwnedStringLexStream : public LexStream {
 public:
  explicit OwnedStringLexStream(std::string data) : data_(std::move(data)) {}

  size_t read(char *buffer, size_t size) override {
    auto remaining = data_.size() - offset_;
    auto count = remaining < size ? remaining : size;
    if (count > 0) {
      std::memcpy(buffer, data_.data() + offset_, count);
      offset_ += count;
    }
    return count;
  }

  void close() override { offset_ = data_.size(); }

 private:
  std::string data_;
  size_t offset_{0};
};

bool is_utf8_encoding(const std::string &encoding) {
  return ucnv_compareNames(kLpcInternalStringEncoding, encoding.c_str()) == 0;
}

std::string read_all(LexStream *stream) {
  std::string data;
  char buffer[8192];
  while (true) {
    auto count = stream->read(buffer, sizeof(buffer));
    if (count == 0) {
      break;
    }
    data.append(buffer, count);
    if (count < sizeof(buffer)) {
      break;
    }
  }
  return data;
}

std::string convert_to_utf8(const std::string &source, const std::string &encoding,
                            int *invalid_sequence_count, std::string *error) {
  UErrorCode error_code = U_ZERO_ERROR;
  auto *converter = ucnv_open(encoding.c_str(), &error_code);
  if (U_FAILURE(error_code)) {
    *error = std::string("invalid source encoding '") + encoding + "': " + u_errorName(error_code);
    return {};
  }

  error_code = U_ZERO_ERROR;
  auto required = ucnv_toAlgorithmic(UCNV_UTF8, converter, nullptr, 0, source.data(),
                                    static_cast<int32_t>(source.size()), &error_code);
  if (U_FAILURE(error_code) && error_code != U_BUFFER_OVERFLOW_ERROR) {
    *invalid_sequence_count += 1;
    *error = std::string("source encoding conversion failed: ") + u_errorName(error_code);
    ucnv_close(converter);
    return {};
  }

  std::string result(static_cast<size_t>(required), '\0');
  error_code = U_ZERO_ERROR;
  auto written = ucnv_toAlgorithmic(UCNV_UTF8, converter, result.data(), required, source.data(),
                                    static_cast<int32_t>(source.size()), &error_code);
  ucnv_close(converter);
  if (U_FAILURE(error_code) || written != required) {
    *invalid_sequence_count += 1;
    *error = std::string("source encoding conversion failed: ") + u_errorName(error_code);
    return {};
  }
  return result;
}
}  // namespace

LpcSourceEncodingResult lpc_source_decode_to_utf8(const std::string &source) {
  LpcSourceEncodingResult result;
  result.encoding = lpc_source_encoding_from_source(source);
  if (result.encoding.empty()) {
    result.encoding = kLpcInternalStringEncoding;
  }
  if (is_utf8_encoding(result.encoding)) {
    result.data = source;
    return result;
  }
  result.data = convert_to_utf8(source, result.encoding, &result.invalid_sequence_count, &result.error);
  result.transcoded = result.error.empty();
  if (!result.transcoded) {
    result.data = source;
  }
  return result;
}

std::unique_ptr<LexStream> lpc_source_encoding_stream(std::unique_ptr<LexStream> source) {
  auto data = read_all(source.get());
  source->close();
  auto decoded = lpc_source_decode_to_utf8(data);
  return std::make_unique<OwnedStringLexStream>(std::move(decoded.data));
}
