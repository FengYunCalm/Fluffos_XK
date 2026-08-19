void do_tests() {
  float* m = id_matrix();
  m = lookat_rotate2(m, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1);

  // #1247 MATRIX-1..7: every transform requires a 16-element array; a short
  // array must error out, not read past the array end.
  mixed err;
  err = catch(translate(({ 1, 2, 3 }), 1.0, 2.0, 3.0));
  ASSERT(err);
  err = catch(scale(({ 1, 2, 3 }), 1.0, 2.0, 3.0));
  ASSERT(err);
  err = catch(rotate_x(({ 1, 2, 3 }), 1.0));
  ASSERT(err);
  err = catch(rotate_y(({ 1, 2, 3 }), 1.0));
  ASSERT(err);
  err = catch(rotate_z(({ 1, 2, 3 }), 1.0));
  ASSERT(err);
  err = catch(lookat_rotate(({ 1, 2, 3 }), 1.0, 2.0, 3.0));
  ASSERT(err);
  err = catch(lookat_rotate2(({ 1, 2, 3 }), 1.0, 2.0, 3.0, 4.0, 5.0, 6.0));
  ASSERT(err);
}
