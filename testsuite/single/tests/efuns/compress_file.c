void do_tests() {
#ifndef __PACKAGE_COMPRESS__
  write("compress package not enabled, skipped.\n");
  return;
#else
  string source = "/compress_file_path_test";
  string compressed = source + ".gz";
  string explicit_output = "/compress_file_path_test.explicit.gz";
  string restored = "/compress_file_path_test.restored";

  rm(source);
  rm(compressed);
  rm(explicit_output);
  rm(restored);

  ASSERT_EQ(0, compress_file("x"));
  ASSERT_EQ(0, uncompress_file("x"));

  ASSERT_EQ(1, write_file(source, "compress path regression\n"));
  ASSERT_EQ(1, compress_file(source));
  ASSERT_EQ(-1, file_size(source));
  ASSERT(file_size(compressed) > 0);

  ASSERT_EQ(1, uncompress_file(compressed));
  ASSERT_EQ(-1, file_size(compressed));
  ASSERT_EQ("compress path regression\n", read_file(source));

  ASSERT_EQ(1, compress_file(source, explicit_output));
  ASSERT_EQ(-1, file_size(source));
  ASSERT(file_size(explicit_output) > 0);

  ASSERT_EQ(1, uncompress_file(explicit_output, restored));
  ASSERT_EQ(-1, file_size(explicit_output));
  ASSERT_EQ("compress path regression\n", read_file(restored));

  rm(source);
  rm(compressed);
  rm(explicit_output);
  rm(restored);
#endif
}
