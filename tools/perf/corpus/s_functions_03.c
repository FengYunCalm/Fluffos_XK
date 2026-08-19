// representative: many small functions, default args, varargs
int add_3(int a, int b) { return a + b; }
int sub_3(int a, int b) { return a - b; }
int mul_3(int a, int b) { return a * b; }
int div_3(int a, int b) { return b ? a / b : 0; }
int mod_3(int a, int b) { return b ? a % b : 0; }
int neg_3(int a) { return -a; }
int abs_3(int a) { return a < 0 ? -a : a; }
int clamp_3(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_3(int a, int b, int c) { return a + b + c; }
int sum_varargs_3(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_3_0 = 494;
int pad_3_1 = 724;
int pad_3_2 = 383;
int pad_3_3 = 83;
int pad_3_4 = 785;
int pad_3_5 = 984;
int pad_3_6 = 69;
int pad_3_7 = 541;
int pad_3_8 = 828;
int pad_3_9 = 340;
int pad_3_10 = 802;
int pad_3_11 = 564;
int pad_3_12 = 743;
int pad_3_13 = 944;
int pad_3_14 = 106;
int pad_3_15 = 123;
int pad_3_16 = 461;
int pad_3_17 = 65;
int pad_3_18 = 785;
int pad_3_19 = 254;
int pad_3_20 = 823;
int pad_3_21 = 710;
int pad_3_22 = 622;
int pad_3_23 = 986;
int pad_3_24 = 21;
int pad_3_25 = 279;
int pad_3_26 = 965;
int pad_3_27 = 808;
int pad_3_28 = 632;
int pad_3_29 = 740;
int pad_3_30 = 590;
int pad_3_31 = 342;
int pad_3_32 = 429;
int pad_3_33 = 119;
int pad_3_34 = 0;
int pad_3_35 = 772;
int pad_3_36 = 694;
int pad_3_37 = 624;
int pad_3_38 = 404;
int pad_3_39 = 686;
int pad_3_40 = 64;
int pad_3_41 = 965;
int pad_3_42 = 626;
int pad_3_43 = 496;
int pad_3_44 = 462;
int pad_3_45 = 833;
int pad_3_46 = 244;
int pad_3_47 = 352;
int pad_3_48 = 931;
int pad_3_49 = 411;
int pad_3_50 = 342;
int pad_3_51 = 469;
int pad_3_52 = 728;
int pad_3_53 = 630;
int pad_3_54 = 226;
int pad_3_55 = 793;
int pad_3_56 = 527;
int pad_3_57 = 475;
int pad_3_58 = 161;
int pad_3_59 = 965;
int pad_3_60 = 415;
int pad_3_61 = 596;
int pad_3_62 = 150;
int pad_3_63 = 671;
int pad_3_64 = 566;
int pad_3_65 = 995;
int pad_3_66 = 454;
int pad_3_67 = 153;
int pad_3_68 = 285;
int pad_3_69 = 326;
int pad_3_70 = 228;
int pad_3_71 = 482;
int pad_3_72 = 577;
int pad_3_73 = 232;
int pad_3_74 = 916;
int pad_3_75 = 47;
int pad_3_76 = 602;
int pad_3_77 = 475;
int pad_3_78 = 935;
int pad_3_79 = 360;
int pad_3_80 = 417;
int pad_3_81 = 146;
int pad_3_82 = 55;
int pad_3_83 = 593;
int pad_3_84 = 798;
