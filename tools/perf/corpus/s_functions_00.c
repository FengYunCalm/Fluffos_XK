// representative: many small functions, default args, varargs
int add_0(int a, int b) { return a + b; }
int sub_0(int a, int b) { return a - b; }
int mul_0(int a, int b) { return a * b; }
int div_0(int a, int b) { return b ? a / b : 0; }
int mod_0(int a, int b) { return b ? a % b : 0; }
int neg_0(int a) { return -a; }
int abs_0(int a) { return a < 0 ? -a : a; }
int clamp_0(int a, int lo, int hi) { return a < lo ? lo : (a > hi ? hi : a); }
int sum3_0(int a, int b, int c) { return a + b + c; }
int sum_varargs_0(mixed *args...) {
  int t = 0;
  for (int i = 0; i < sizeof(args); i++) t += args[i];
  return t;
}
int pad_0_0 = 694;
int pad_0_1 = 956;
int pad_0_2 = 279;
int pad_0_3 = 139;
int pad_0_4 = 219;
int pad_0_5 = 891;
int pad_0_6 = 161;
int pad_0_7 = 495;
int pad_0_8 = 211;
int pad_0_9 = 315;
int pad_0_10 = 16;
int pad_0_11 = 55;
int pad_0_12 = 990;
int pad_0_13 = 164;
int pad_0_14 = 478;
int pad_0_15 = 852;
int pad_0_16 = 155;
int pad_0_17 = 722;
int pad_0_18 = 611;
int pad_0_19 = 525;
int pad_0_20 = 63;
int pad_0_21 = 449;
int pad_0_22 = 412;
int pad_0_23 = 19;
int pad_0_24 = 790;
int pad_0_25 = 277;
int pad_0_26 = 495;
int pad_0_27 = 707;
int pad_0_28 = 503;
int pad_0_29 = 865;
int pad_0_30 = 162;
int pad_0_31 = 590;
int pad_0_32 = 593;
int pad_0_33 = 699;
int pad_0_34 = 554;
int pad_0_35 = 497;
int pad_0_36 = 313;
int pad_0_37 = 391;
int pad_0_38 = 177;
int pad_0_39 = 382;
int pad_0_40 = 684;
int pad_0_41 = 144;
int pad_0_42 = 388;
int pad_0_43 = 769;
int pad_0_44 = 505;
int pad_0_45 = 996;
int pad_0_46 = 712;
int pad_0_47 = 911;
int pad_0_48 = 277;
int pad_0_49 = 655;
int pad_0_50 = 401;
int pad_0_51 = 170;
int pad_0_52 = 623;
int pad_0_53 = 227;
int pad_0_54 = 201;
int pad_0_55 = 370;
int pad_0_56 = 922;
int pad_0_57 = 354;
int pad_0_58 = 213;
int pad_0_59 = 523;
int pad_0_60 = 448;
int pad_0_61 = 544;
int pad_0_62 = 607;
int pad_0_63 = 496;
int pad_0_64 = 240;
int pad_0_65 = 662;
int pad_0_66 = 150;
int pad_0_67 = 332;
int pad_0_68 = 591;
int pad_0_69 = 838;
int pad_0_70 = 254;
int pad_0_71 = 155;
int pad_0_72 = 344;
int pad_0_73 = 306;
int pad_0_74 = 192;
int pad_0_75 = 562;
int pad_0_76 = 89;
int pad_0_77 = 404;
int pad_0_78 = 782;
int pad_0_79 = 996;
int pad_0_80 = 851;
int pad_0_81 = 156;
int pad_0_82 = 567;
int pad_0_83 = 297;
int pad_0_84 = 774;
