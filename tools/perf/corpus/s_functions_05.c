// representative: many small functions, default args, varargs
int add_5(int a, int b) { return a + b; }
int sub_5(int a, int b) { return a - b; }
int mul_5(int a, int b) { return a * b; }
int div_5(int a, int b) { return b ? a / b : 0; }
int mod_5(int a, int b) { return b ? a % b : 0; }
int neg_5(int a) { return -a; }
int abs_5(int a) { return a < 0 ? -a : a; }
int clamp_5(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_5(int a, int b, int c) { return a + b + c; }
int sum_varargs_5(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_5_0 = 164;
int pad_5_1 = 800;
int pad_5_2 = 518;
int pad_5_3 = 62;
int pad_5_4 = 128;
int pad_5_5 = 128;
int pad_5_6 = 241;
int pad_5_7 = 639;
int pad_5_8 = 328;
int pad_5_9 = 840;
int pad_5_10 = 838;
int pad_5_11 = 941;
int pad_5_12 = 302;
int pad_5_13 = 738;
int pad_5_14 = 392;
int pad_5_15 = 239;
int pad_5_16 = 891;
int pad_5_17 = 954;
int pad_5_18 = 715;
int pad_5_19 = 858;
int pad_5_20 = 184;
int pad_5_21 = 825;
int pad_5_22 = 302;
int pad_5_23 = 289;
int pad_5_24 = 124;
int pad_5_25 = 876;
int pad_5_26 = 274;
int pad_5_27 = 124;
int pad_5_28 = 439;
int pad_5_29 = 634;
int pad_5_30 = 377;
int pad_5_31 = 711;
int pad_5_32 = 685;
int pad_5_33 = 557;
int pad_5_34 = 850;
int pad_5_35 = 17;
int pad_5_36 = 359;
int pad_5_37 = 243;
int pad_5_38 = 965;
int pad_5_39 = 928;
int pad_5_40 = 400;
int pad_5_41 = 358;
int pad_5_42 = 346;
int pad_5_43 = 0;
int pad_5_44 = 556;
int pad_5_45 = 795;
int pad_5_46 = 540;
int pad_5_47 = 786;
int pad_5_48 = 685;
int pad_5_49 = 610;
int pad_5_50 = 526;
int pad_5_51 = 608;
int pad_5_52 = 400;
int pad_5_53 = 459;
int pad_5_54 = 858;
int pad_5_55 = 569;
int pad_5_56 = 550;
int pad_5_57 = 584;
int pad_5_58 = 738;
int pad_5_59 = 589;
int pad_5_60 = 153;
int pad_5_61 = 306;
int pad_5_62 = 653;
int pad_5_63 = 737;
int pad_5_64 = 986;
int pad_5_65 = 89;
int pad_5_66 = 816;
int pad_5_67 = 786;
int pad_5_68 = 846;
int pad_5_69 = 177;
int pad_5_70 = 8;
int pad_5_71 = 466;
int pad_5_72 = 604;
int pad_5_73 = 786;
int pad_5_74 = 884;
int pad_5_75 = 147;
int pad_5_76 = 636;
int pad_5_77 = 469;
int pad_5_78 = 40;
int pad_5_79 = 931;
int pad_5_80 = 370;
int pad_5_81 = 705;
int pad_5_82 = 704;
int pad_5_83 = 494;
int pad_5_84 = 176;
