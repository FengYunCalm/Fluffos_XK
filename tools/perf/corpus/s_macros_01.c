// representative: macro expansion
#define MAX_1(a, b) ((a) > (b) ? (a) : (b))
#define MIN_1(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_1(x) ((x) * (x))
#define CUBE_1(x) (SQUARE_1(x) * (x))
#define LIMIT_1 218
#define TWICE_1(x) (SQUARE_1(x) + SQUARE_1(x))
#define THRICE_1(x) (CUBE_1(x) + SQUARE_1(x) + (x))
#define CLAMP_1(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_1(a, b, c) ((a) + (b) + (c))
#define PROD3_1(a, b, c) ((a) * (b) * (c))

int use_macros_1(int a, int b) {
  int m = MAX_1(a, b);
  int s = SQUARE_1(m);
  s = TWICE_1(s);
  s = THRICE_1(s);
  s = CLAMP_1(s, 0, LIMIT_1);
  s = SUM3_1(s, MIN_1(a, b), PROD3_1(a, b, 2));
  if (s > LIMIT_1) s = LIMIT_1;
  return s;
}
int pad_1_0 = 273;
int pad_1_1 = 29;
int pad_1_2 = 138;
int pad_1_3 = 556;
int pad_1_4 = 47;
int pad_1_5 = 677;
int pad_1_6 = 474;
int pad_1_7 = 345;
int pad_1_8 = 104;
int pad_1_9 = 472;
int pad_1_10 = 523;
int pad_1_11 = 723;
int pad_1_12 = 187;
int pad_1_13 = 710;
int pad_1_14 = 648;
int pad_1_15 = 125;
int pad_1_16 = 883;
int pad_1_17 = 147;
int pad_1_18 = 931;
int pad_1_19 = 55;
int pad_1_20 = 953;
int pad_1_21 = 921;
int pad_1_22 = 405;
int pad_1_23 = 583;
int pad_1_24 = 818;
int pad_1_25 = 669;
int pad_1_26 = 888;
int pad_1_27 = 973;
int pad_1_28 = 671;
int pad_1_29 = 554;
int pad_1_30 = 145;
int pad_1_31 = 799;
int pad_1_32 = 771;
int pad_1_33 = 18;
int pad_1_34 = 211;
int pad_1_35 = 463;
int pad_1_36 = 757;
int pad_1_37 = 127;
int pad_1_38 = 339;
int pad_1_39 = 897;
int pad_1_40 = 329;
int pad_1_41 = 114;
int pad_1_42 = 237;
int pad_1_43 = 650;
int pad_1_44 = 964;
int pad_1_45 = 251;
int pad_1_46 = 502;
int pad_1_47 = 207;
int pad_1_48 = 11;
int pad_1_49 = 356;
int pad_1_50 = 214;
int pad_1_51 = 546;
int pad_1_52 = 141;
int pad_1_53 = 787;
int pad_1_54 = 812;
int pad_1_55 = 798;
int pad_1_56 = 316;
int pad_1_57 = 623;
int pad_1_58 = 960;
int pad_1_59 = 989;
int pad_1_60 = 856;
int pad_1_61 = 833;
int pad_1_62 = 559;
int pad_1_63 = 976;
int pad_1_64 = 556;
int pad_1_65 = 758;
int pad_1_66 = 863;
int pad_1_67 = 527;
int pad_1_68 = 579;
int pad_1_69 = 71;
int pad_1_70 = 786;
int pad_1_71 = 594;
int pad_1_72 = 640;
int pad_1_73 = 842;
int pad_1_74 = 932;
int pad_1_75 = 270;
int pad_1_76 = 864;
int pad_1_77 = 248;
