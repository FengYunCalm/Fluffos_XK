// representative: many small functions, default args, varargs
int add_6(int a, int b) { return a + b; }
int sub_6(int a, int b) { return a - b; }
int mul_6(int a, int b) { return a * b; }
int div_6(int a, int b) { return b ? a / b : 0; }
int mod_6(int a, int b) { return b ? a % b : 0; }
int neg_6(int a) { return -a; }
int abs_6(int a) { return a < 0 ? -a : a; }
int clamp_6(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_6(int a, int b, int c) { return a + b + c; }
int sum_varargs_6(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_6_0 = 980;
int pad_6_1 = 707;
int pad_6_2 = 409;
int pad_6_3 = 715;
int pad_6_4 = 182;
int pad_6_5 = 934;
int pad_6_6 = 400;
int pad_6_7 = 788;
int pad_6_8 = 208;
int pad_6_9 = 393;
int pad_6_10 = 718;
int pad_6_11 = 938;
int pad_6_12 = 917;
int pad_6_13 = 319;
int pad_6_14 = 343;
int pad_6_15 = 5;
int pad_6_16 = 690;
int pad_6_17 = 633;
int pad_6_18 = 597;
int pad_6_19 = 995;
int pad_6_20 = 527;
int pad_6_21 = 929;
int pad_6_22 = 318;
int pad_6_23 = 362;
int pad_6_24 = 295;
int pad_6_25 = 151;
int pad_6_26 = 436;
int pad_6_27 = 27;
int pad_6_28 = 361;
int pad_6_29 = 967;
int pad_6_30 = 231;
int pad_6_31 = 986;
int pad_6_32 = 442;
int pad_6_33 = 334;
int pad_6_34 = 190;
int pad_6_35 = 799;
int pad_6_36 = 293;
int pad_6_37 = 543;
int pad_6_38 = 488;
int pad_6_39 = 219;
int pad_6_40 = 222;
int pad_6_41 = 616;
int pad_6_42 = 337;
int pad_6_43 = 11;
int pad_6_44 = 359;
int pad_6_45 = 121;
int pad_6_46 = 942;
int pad_6_47 = 858;
int pad_6_48 = 803;
int pad_6_49 = 168;
int pad_6_50 = 276;
int pad_6_51 = 399;
int pad_6_52 = 161;
int pad_6_53 = 232;
int pad_6_54 = 667;
int pad_6_55 = 847;
int pad_6_56 = 22;
int pad_6_57 = 623;
int pad_6_58 = 917;
int pad_6_59 = 378;
int pad_6_60 = 624;
int pad_6_61 = 145;
int pad_6_62 = 343;
int pad_6_63 = 376;
int pad_6_64 = 983;
int pad_6_65 = 930;
int pad_6_66 = 114;
int pad_6_67 = 207;
int pad_6_68 = 991;
int pad_6_69 = 250;
int pad_6_70 = 457;
int pad_6_71 = 484;
int pad_6_72 = 863;
int pad_6_73 = 639;
int pad_6_74 = 454;
int pad_6_75 = 989;
int pad_6_76 = 311;
int pad_6_77 = 658;
int pad_6_78 = 549;
int pad_6_79 = 980;
int pad_6_80 = 598;
int pad_6_81 = 479;
int pad_6_82 = 98;
int pad_6_83 = 829;
int pad_6_84 = 272;
