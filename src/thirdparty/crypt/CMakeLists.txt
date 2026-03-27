project(crypt CXX)

if (MSVC)
  add_compile_options(/w)
elseif (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-w)
endif ()

set(SOURCE
  "include/crypt.h"
  "crypt.h"
  "crypt.c"
  "crypt_blowfish.c"
  "crypt_des.c"
  "crypt_des.h"
  "crypt_md5.c"
  "crypt_r.c"
  "crypt_sha256.c"
  "crypt_sha512.c"
  "encrypt.c"
)

add_library(crypt STATIC ${SOURCE})

if (TARGET crypt)
  set_property(TARGET crypt PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
endif ()
