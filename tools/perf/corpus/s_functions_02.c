// representative: many small functions, default args, varargs
int add_2(int a, int b) { return a + b; }
int sub_2(int a, int b) { return a - b; }
int mul_2(int a, int b) { return a * b; }
int div_2(int a, int b) { return b ? a / b : 0; }
int mod_2(int a, int b) { return b ? a % b : 0; }
int neg_2(int a) { return -a; }
int abs_2(int a) { return a < 0 ? -a : a; }
int clamp_2(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_2(int a, int b, int c) { return a + b + c; }
int sum_varargs_2(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_2_0 = 354;
int pad_2_1 = 822;
int pad_2_2 = 321;
int pad_2_3 = 73;
int pad_2_4 = 137;
int pad_2_5 = 486;
int pad_2_6 = 75;
int pad_2_7 = 926;
int pad_2_8 = 876;
int pad_2_9 = 509;
int pad_2_10 = 735;
int pad_2_11 = 572;
int pad_2_12 = 600;
int pad_2_13 = 372;
int pad_2_14 = 966;
int pad_2_15 = 326;
int pad_2_16 = 766;
int pad_2_17 = 43;
int pad_2_18 = 893;
int pad_2_19 = 561;
int pad_2_20 = 858;
int pad_2_21 = 555;
int pad_2_22 = 153;
int pad_2_23 = 574;
int pad_2_24 = 558;
int pad_2_25 = 786;
int pad_2_26 = 27;
int pad_2_27 = 377;
int pad_2_28 = 577;
int pad_2_29 = 45;
int pad_2_30 = 889;
int pad_2_31 = 503;
int pad_2_32 = 90;
int pad_2_33 = 427;
int pad_2_34 = 325;
int pad_2_35 = 785;
int pad_2_36 = 229;
int pad_2_37 = 916;
int pad_2_38 = 801;
int pad_2_39 = 588;
int pad_2_40 = 918;
int pad_2_41 = 862;
int pad_2_42 = 885;
int pad_2_43 = 195;
int pad_2_44 = 913;
int pad_2_45 = 30;
int pad_2_46 = 577;
int pad_2_47 = 374;
int pad_2_48 = 328;
int pad_2_49 = 281;
int pad_2_50 = 287;
int pad_2_51 = 308;
int pad_2_52 = 731;
int pad_2_53 = 501;
int pad_2_54 = 773;
int pad_2_55 = 421;
int pad_2_56 = 372;
int pad_2_57 = 744;
int pad_2_58 = 611;
int pad_2_59 = 258;
int pad_2_60 = 269;
int pad_2_61 = 492;
int pad_2_62 = 106;
int pad_2_63 = 644;
int pad_2_64 = 908;
int pad_2_65 = 904;
int pad_2_66 = 210;
int pad_2_67 = 404;
int pad_2_68 = 268;
int pad_2_69 = 563;
int pad_2_70 = 367;
int pad_2_71 = 937;
int pad_2_72 = 218;
int pad_2_73 = 102;
int pad_2_74 = 623;
int pad_2_75 = 989;
int pad_2_76 = 592;
int pad_2_77 = 994;
int pad_2_78 = 796;
int pad_2_79 = 563;
int pad_2_80 = 96;
int pad_2_81 = 562;
int pad_2_82 = 32;
int pad_2_83 = 881;
int pad_2_84 = 978;
