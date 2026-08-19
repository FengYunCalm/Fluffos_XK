// representative: many small functions, default args, varargs
int add_1(int a, int b) { return a + b; }
int sub_1(int a, int b) { return a - b; }
int mul_1(int a, int b) { return a * b; }
int div_1(int a, int b) { return b ? a / b : 0; }
int mod_1(int a, int b) { return b ? a % b : 0; }
int neg_1(int a) { return -a; }
int abs_1(int a) { return a < 0 ? -a : a; }
int clamp_1(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_1(int a, int b, int c) { return a + b + c; }
int sum_varargs_1(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_1_0 = 416;
int pad_1_1 = 203;
int pad_1_2 = 619;
int pad_1_3 = 746;
int pad_1_4 = 234;
int pad_1_5 = 140;
int pad_1_6 = 16;
int pad_1_7 = 888;
int pad_1_8 = 634;
int pad_1_9 = 925;
int pad_1_10 = 737;
int pad_1_11 = 28;
int pad_1_12 = 339;
int pad_1_13 = 829;
int pad_1_14 = 801;
int pad_1_15 = 893;
int pad_1_16 = 196;
int pad_1_17 = 99;
int pad_1_18 = 765;
int pad_1_19 = 84;
int pad_1_20 = 659;
int pad_1_21 = 693;
int pad_1_22 = 205;
int pad_1_23 = 663;
int pad_1_24 = 589;
int pad_1_25 = 411;
int pad_1_26 = 462;
int pad_1_27 = 75;
int pad_1_28 = 811;
int pad_1_29 = 866;
int pad_1_30 = 227;
int pad_1_31 = 852;
int pad_1_32 = 197;
int pad_1_33 = 460;
int pad_1_34 = 744;
int pad_1_35 = 440;
int pad_1_36 = 984;
int pad_1_37 = 160;
int pad_1_38 = 835;
int pad_1_39 = 459;
int pad_1_40 = 637;
int pad_1_41 = 180;
int pad_1_42 = 935;
int pad_1_43 = 273;
int pad_1_44 = 467;
int pad_1_45 = 98;
int pad_1_46 = 451;
int pad_1_47 = 19;
int pad_1_48 = 630;
int pad_1_49 = 933;
int pad_1_50 = 436;
int pad_1_51 = 374;
int pad_1_52 = 958;
int pad_1_53 = 274;
int pad_1_54 = 9;
int pad_1_55 = 806;
int pad_1_56 = 645;
int pad_1_57 = 659;
int pad_1_58 = 829;
int pad_1_59 = 488;
int pad_1_60 = 324;
int pad_1_61 = 468;
int pad_1_62 = 802;
int pad_1_63 = 39;
int pad_1_64 = 990;
int pad_1_65 = 815;
int pad_1_66 = 271;
int pad_1_67 = 153;
int pad_1_68 = 749;
int pad_1_69 = 301;
int pad_1_70 = 443;
int pad_1_71 = 187;
int pad_1_72 = 422;
int pad_1_73 = 870;
int pad_1_74 = 308;
int pad_1_75 = 973;
int pad_1_76 = 843;
int pad_1_77 = 256;
int pad_1_78 = 417;
int pad_1_79 = 883;
int pad_1_80 = 183;
int pad_1_81 = 359;
int pad_1_82 = 236;
int pad_1_83 = 197;
int pad_1_84 = 988;
