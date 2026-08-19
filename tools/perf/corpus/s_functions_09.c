// representative: many small functions, default args, varargs
int add_9(int a, int b) { return a + b; }
int sub_9(int a, int b) { return a - b; }
int mul_9(int a, int b) { return a * b; }
int div_9(int a, int b) { return b ? a / b : 0; }
int mod_9(int a, int b) { return b ? a % b : 0; }
int neg_9(int a) { return -a; }
int abs_9(int a) { return a < 0 ? -a : a; }
int clamp_9(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_9(int a, int b, int c) { return a + b + c; }
int sum_varargs_9(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_9_0 = 681;
int pad_9_1 = 492;
int pad_9_2 = 438;
int pad_9_3 = 567;
int pad_9_4 = 243;
int pad_9_5 = 259;
int pad_9_6 = 194;
int pad_9_7 = 906;
int pad_9_8 = 493;
int pad_9_9 = 387;
int pad_9_10 = 208;
int pad_9_11 = 547;
int pad_9_12 = 740;
int pad_9_13 = 578;
int pad_9_14 = 113;
int pad_9_15 = 556;
int pad_9_16 = 376;
int pad_9_17 = 569;
int pad_9_18 = 268;
int pad_9_19 = 771;
int pad_9_20 = 190;
int pad_9_21 = 403;
int pad_9_22 = 220;
int pad_9_23 = 708;
int pad_9_24 = 924;
int pad_9_25 = 444;
int pad_9_26 = 908;
int pad_9_27 = 144;
int pad_9_28 = 673;
int pad_9_29 = 647;
int pad_9_30 = 10;
int pad_9_31 = 406;
int pad_9_32 = 962;
int pad_9_33 = 178;
int pad_9_34 = 883;
int pad_9_35 = 874;
int pad_9_36 = 639;
int pad_9_37 = 319;
int pad_9_38 = 275;
int pad_9_39 = 386;
int pad_9_40 = 130;
int pad_9_41 = 449;
int pad_9_42 = 868;
int pad_9_43 = 219;
int pad_9_44 = 911;
int pad_9_45 = 49;
int pad_9_46 = 609;
int pad_9_47 = 81;
int pad_9_48 = 938;
int pad_9_49 = 971;
int pad_9_50 = 495;
int pad_9_51 = 164;
int pad_9_52 = 188;
int pad_9_53 = 293;
int pad_9_54 = 407;
int pad_9_55 = 166;
int pad_9_56 = 779;
int pad_9_57 = 86;
int pad_9_58 = 263;
int pad_9_59 = 344;
int pad_9_60 = 785;
int pad_9_61 = 972;
int pad_9_62 = 670;
int pad_9_63 = 54;
int pad_9_64 = 605;
int pad_9_65 = 254;
int pad_9_66 = 99;
int pad_9_67 = 798;
int pad_9_68 = 176;
int pad_9_69 = 477;
int pad_9_70 = 360;
int pad_9_71 = 649;
int pad_9_72 = 453;
int pad_9_73 = 470;
int pad_9_74 = 215;
int pad_9_75 = 580;
int pad_9_76 = 748;
int pad_9_77 = 238;
int pad_9_78 = 189;
int pad_9_79 = 57;
int pad_9_80 = 355;
int pad_9_81 = 434;
int pad_9_82 = 909;
int pad_9_83 = 642;
int pad_9_84 = 959;
