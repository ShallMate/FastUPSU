if(CMAKE_SIZEOF_VOID_P LESS 8)
  message(FATAL_ERROR "UPSU requires a 64-bit platform")
endif()
