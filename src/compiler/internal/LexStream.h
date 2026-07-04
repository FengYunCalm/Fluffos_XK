#ifndef LEX_STREAM_H
#define LEX_STREAM_H

#include "base/std.h"

#include <cinttypes>
#include <cstddef>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <sstream>

class LexStream {
 public:
  LexStream() = default;
  virtual ~LexStream() = default;

  virtual size_t read(char* buffer, size_t size) = 0;
  virtual void close() = 0;
};

class FileLexStream : public LexStream {
 public:
  FileLexStream(int fd) : fd_(fd) {}
  ~FileLexStream() override { close(); }

  size_t read(char* buffer, size_t size) override {
    if (fd_ < 0) {
      return 0;
    }
    auto bytes = ::read(fd_, buffer, size);
    return bytes > 0 ? static_cast<size_t>(bytes) : 0;
  }
  void close() override {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  };

 private:
  int fd_;
};

class IStreamLexStream : public LexStream {
 public:
  IStreamLexStream(std::istream& is) : is_(is) {}
  ~IStreamLexStream() override {}

  size_t read(char* buffer, size_t size) override { return is_.readsome(buffer, size); }
  void close() override { is_.clear(); };

 private:
  std::istream& is_;
};

#endif /* end of include guard: LEX_STREAM_H */
