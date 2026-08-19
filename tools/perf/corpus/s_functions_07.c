// representative: many small functions, default args, varargs
int add_7(int a, int b) { return a + b; }
int sub_7(int a, int b) { return a - b; }
int mul_7(int a, int b) { return a * b; }
int div_7(int a, int b) { return b ? a / b : 0; }
int mod_7(int a, int b) { return b ? a % b : 0; }
int neg_7(int a) { return -a; }
int abs_7(int a) { return a < 0 ? -a : a; }
int clamp_7(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_7(int a, int b, int c) { return a + b + c; }
int sum_varargs_7(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_7_0 = 867;
int pad_7_1 = 713;
int pad_7_2 = 733;
int pad_7_3 = 44;
int pad_7_4 = 717;
int pad_7_5 = 455;
int pad_7_6 = 68;
int pad_7_7 = 466;
int pad_7_8 = 924;
int pad_7_9 = 999;
int pad_7_10 = 258;
int pad_7_11 = 89;
int pad_7_12 = 859;
int pad_7_13 = 991;
int pad_7_14 = 474;
int pad_7_15 = 637;
int pad_7_16 = 505;
int pad_7_17 = 596;
int pad_7_18 = 466;
int pad_7_19 = 990;
int pad_7_20 = 823;
int pad_7_21 = 449;
int pad_7_22 = 116;
int pad_7_23 = 789;
int pad_7_24 = 36;
int pad_7_25 = 902;
int pad_7_26 = 694;
int pad_7_27 = 819;
int pad_7_28 = 414;
int pad_7_29 = 982;
int pad_7_30 = 381;
int pad_7_31 = 671;
int pad_7_32 = 354;
int pad_7_33 = 190;
int pad_7_34 = 33;
int pad_7_35 = 428;
int pad_7_36 = 447;
int pad_7_37 = 126;
int pad_7_38 = 71;
int pad_7_39 = 167;
int pad_7_40 = 160;
int pad_7_41 = 892;
int pad_7_42 = 416;
int pad_7_43 = 847;
int pad_7_44 = 111;
int pad_7_45 = 221;
int pad_7_46 = 419;
int pad_7_47 = 2;
int pad_7_48 = 3;
int pad_7_49 = 566;
int pad_7_50 = 423;
int pad_7_51 = 746;
int pad_7_52 = 665;
int pad_7_53 = 301;
int pad_7_54 = 99;
int pad_7_55 = 837;
int pad_7_56 = 652;
int pad_7_57 = 336;
int pad_7_58 = 94;
int pad_7_59 = 93;
int pad_7_60 = 701;
int pad_7_61 = 400;
int pad_7_62 = 14;
int pad_7_63 = 463;
int pad_7_64 = 29;
int pad_7_65 = 640;
int pad_7_66 = 180;
int pad_7_67 = 965;
int pad_7_68 = 272;
int pad_7_69 = 104;
int pad_7_70 = 633;
int pad_7_71 = 283;
int pad_7_72 = 978;
int pad_7_73 = 974;
int pad_7_74 = 809;
int pad_7_75 = 956;
int pad_7_76 = 940;
int pad_7_77 = 551;
int pad_7_78 = 336;
int pad_7_79 = 220;
int pad_7_80 = 743;
int pad_7_81 = 171;
int pad_7_82 = 475;
int pad_7_83 = 317;
int pad_7_84 = 122;
