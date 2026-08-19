// representative: many small functions, default args, varargs
int add_8(int a, int b) { return a + b; }
int sub_8(int a, int b) { return a - b; }
int mul_8(int a, int b) { return a * b; }
int div_8(int a, int b) { return b ? a / b : 0; }
int mod_8(int a, int b) { return b ? a % b : 0; }
int neg_8(int a) { return -a; }
int abs_8(int a) { return a < 0 ? -a : a; }
int clamp_8(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_8(int a, int b, int c) { return a + b + c; }
int sum_varargs_8(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_8_0 = 84;
int pad_8_1 = 135;
int pad_8_2 = 702;
int pad_8_3 = 222;
int pad_8_4 = 253;
int pad_8_5 = 871;
int pad_8_6 = 279;
int pad_8_7 = 757;
int pad_8_8 = 589;
int pad_8_9 = 835;
int pad_8_10 = 938;
int pad_8_11 = 34;
int pad_8_12 = 527;
int pad_8_13 = 664;
int pad_8_14 = 309;
int pad_8_15 = 325;
int pad_8_16 = 97;
int pad_8_17 = 403;
int pad_8_18 = 477;
int pad_8_19 = 486;
int pad_8_20 = 515;
int pad_8_21 = 304;
int pad_8_22 = 308;
int pad_8_23 = 337;
int pad_8_24 = 393;
int pad_8_25 = 461;
int pad_8_26 = 265;
int pad_8_27 = 764;
int pad_8_28 = 211;
int pad_8_29 = 726;
int pad_8_30 = 601;
int pad_8_31 = 296;
int pad_8_32 = 129;
int pad_8_33 = 861;
int pad_8_34 = 411;
int pad_8_35 = 659;
int pad_8_36 = 98;
int pad_8_37 = 27;
int pad_8_38 = 174;
int pad_8_39 = 835;
int pad_8_40 = 386;
int pad_8_41 = 291;
int pad_8_42 = 365;
int pad_8_43 = 323;
int pad_8_44 = 305;
int pad_8_45 = 553;
int pad_8_46 = 52;
int pad_8_47 = 247;
int pad_8_48 = 568;
int pad_8_49 = 241;
int pad_8_50 = 64;
int pad_8_51 = 827;
int pad_8_52 = 95;
int pad_8_53 = 20;
int pad_8_54 = 86;
int pad_8_55 = 95;
int pad_8_56 = 925;
int pad_8_57 = 473;
int pad_8_58 = 983;
int pad_8_59 = 214;
int pad_8_60 = 217;
int pad_8_61 = 940;
int pad_8_62 = 172;
int pad_8_63 = 676;
int pad_8_64 = 78;
int pad_8_65 = 238;
int pad_8_66 = 990;
int pad_8_67 = 531;
int pad_8_68 = 398;
int pad_8_69 = 48;
int pad_8_70 = 676;
int pad_8_71 = 130;
int pad_8_72 = 217;
int pad_8_73 = 573;
int pad_8_74 = 119;
int pad_8_75 = 814;
int pad_8_76 = 342;
int pad_8_77 = 65;
int pad_8_78 = 295;
int pad_8_79 = 371;
int pad_8_80 = 35;
int pad_8_81 = 308;
int pad_8_82 = 369;
int pad_8_83 = 84;
int pad_8_84 = 815;
