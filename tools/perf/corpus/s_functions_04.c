// representative: many small functions, default args, varargs
int add_4(int a, int b) { return a + b; }
int sub_4(int a, int b) { return a - b; }
int mul_4(int a, int b) { return a * b; }
int div_4(int a, int b) { return b ? a / b : 0; }
int mod_4(int a, int b) { return b ? a % b : 0; }
int neg_4(int a) { return -a; }
int abs_4(int a) { return a < 0 ? -a : a; }
int clamp_4(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_4(int a, int b, int c) { return a + b + c; }
int sum_varargs_4(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_4_0 = 646;
int pad_4_1 = 964;
int pad_4_2 = 544;
int pad_4_3 = 121;
int pad_4_4 = 260;
int pad_4_5 = 373;
int pad_4_6 = 642;
int pad_4_7 = 643;
int pad_4_8 = 790;
int pad_4_9 = 288;
int pad_4_10 = 486;
int pad_4_11 = 596;
int pad_4_12 = 78;
int pad_4_13 = 820;
int pad_4_14 = 314;
int pad_4_15 = 137;
int pad_4_16 = 501;
int pad_4_17 = 740;
int pad_4_18 = 421;
int pad_4_19 = 713;
int pad_4_20 = 526;
int pad_4_21 = 106;
int pad_4_22 = 780;
int pad_4_23 = 890;
int pad_4_24 = 596;
int pad_4_25 = 479;
int pad_4_26 = 352;
int pad_4_27 = 46;
int pad_4_28 = 699;
int pad_4_29 = 825;
int pad_4_30 = 963;
int pad_4_31 = 680;
int pad_4_32 = 367;
int pad_4_33 = 805;
int pad_4_34 = 747;
int pad_4_35 = 888;
int pad_4_36 = 931;
int pad_4_37 = 990;
int pad_4_38 = 701;
int pad_4_39 = 328;
int pad_4_40 = 369;
int pad_4_41 = 812;
int pad_4_42 = 310;
int pad_4_43 = 126;
int pad_4_44 = 357;
int pad_4_45 = 327;
int pad_4_46 = 571;
int pad_4_47 = 808;
int pad_4_48 = 276;
int pad_4_49 = 842;
int pad_4_50 = 824;
int pad_4_51 = 613;
int pad_4_52 = 567;
int pad_4_53 = 390;
int pad_4_54 = 501;
int pad_4_55 = 29;
int pad_4_56 = 539;
int pad_4_57 = 372;
int pad_4_58 = 321;
int pad_4_59 = 905;
int pad_4_60 = 443;
int pad_4_61 = 272;
int pad_4_62 = 977;
int pad_4_63 = 769;
int pad_4_64 = 55;
int pad_4_65 = 846;
int pad_4_66 = 712;
int pad_4_67 = 717;
int pad_4_68 = 529;
int pad_4_69 = 639;
int pad_4_70 = 930;
int pad_4_71 = 284;
int pad_4_72 = 633;
int pad_4_73 = 0;
int pad_4_74 = 553;
int pad_4_75 = 337;
int pad_4_76 = 219;
int pad_4_77 = 314;
int pad_4_78 = 636;
int pad_4_79 = 590;
int pad_4_80 = 783;
int pad_4_81 = 624;
int pad_4_82 = 107;
int pad_4_83 = 593;
int pad_4_84 = 342;
