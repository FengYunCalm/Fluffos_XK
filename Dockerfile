FROM alpine:3.18@sha256:fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7 AS builder

RUN apk add --no-progress --no-cache \
    linux-headers gcc g++ clang-dev make cmake bash \
    mariadb-dev mariadb-static postgresql-dev sqlite-dev sqlite-static\
    openssl-dev openssl-libs-static zlib-dev zlib-static icu-dev icu-static \
    pcre-dev bison git musl-dev libelf-static elfutils-dev zstd-static bzip2-static xz-static

WORKDIR /build

# R2-F09: no pipe-to-tar downloads. jemalloc is downloaded to a file, its
# SHA-256 is verified against third_party/manifest.yaml, and only then is it
# extracted.
RUN wget -q -O jemalloc.tar.bz2 \
      https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2 \
    && echo "2db82d1e7119df3e71b7640219b6dfe84789bc0537983c3b7ac4f7189aecfeaa  jemalloc.tar.bz2" | sha256sum -c - \
    && tar -xjf jemalloc.tar.bz2 \
    && rm jemalloc.tar.bz2

WORKDIR /build/jemalloc-5.3.0

RUN ./configure --prefix=/usr \
    && make \
    && make install

COPY . /build/fluffos
RUN mkdir /build/fluffos/build

WORKDIR /build/fluffos/build
RUN cmake .. -DMARCH_NATIVE=OFF -DSTATIC=ON -DENABLE_LTO=OFF \
    && make install

FROM alpine:3.18@sha256:fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7

RUN apk add --no-progress --no-cache \
    icu-data-full

WORKDIR /fluffos

COPY --from=builder /build/fluffos/build/bin ./bin

ENTRYPOINT ["/fluffos/bin/driver"]
