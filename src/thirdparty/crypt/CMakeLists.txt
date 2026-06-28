project(crypt CXX)

option(ENABLE_LEGACY_DES_CRYPT "Enable legacy DES crypt()/setkey()/encrypt() compatibility" OFF)

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
  "crypt_md5.c"
  "crypt_r.c"
  "crypt_sha256.c"
  "crypt_sha512.c"
)

if (ENABLE_LEGACY_DES_CRYPT)
  list(APPEND SOURCE
    "crypt_des.c"
    "crypt_des.h"
    "encrypt.c"
  )
endif ()

add_library(crypt STATIC ${SOURCE})

if (ENABLE_LEGACY_DES_CRYPT)
  target_compile_definitions(crypt PRIVATE FLUFFOS_ENABLE_LEGACY_DES_CRYPT=1)
endif ()

if (TARGET crypt)
  set_property(TARGET crypt PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
endif ()
