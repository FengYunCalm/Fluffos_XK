// representative: macro expansion
#define MAX_0(a, b) ((a) > (b) ? (a) : (b))
#define MIN_0(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_0(x) ((x) * (x))
#define CUBE_0(x) (SQUARE_0(x) * (x))
#define LIMIT_0 439
#define TWICE_0(x) (SQUARE_0(x) + SQUARE_0(x))
#define THRICE_0(x) (CUBE_0(x) + SQUARE_0(x) + (x))
#define CLAMP_0(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_0(a, b, c) ((a) + (b) + (c))
#define PROD3_0(a, b, c) ((a) * (b) * (c))

int use_macros_0(int a, int b) {
  int m = MAX_0(a, b);
  int s = SQUARE_0(m);
  s = TWICE_0(s);
  s = THRICE_0(s);
  s = CLAMP_0(s, 0, LIMIT_0);
  s = SUM3_0(s, MIN_0(a, b), PROD3_0(a, b, 2));
  if (s > LIMIT_0) s = LIMIT_0;
  return s;
}
int pad_0_0 = 684;
int pad_0_1 = 715;
int pad_0_2 = 597;
int pad_0_3 = 816;
int pad_0_4 = 700;
int pad_0_5 = 108;
int pad_0_6 = 636;
int pad_0_7 = 943;
int pad_0_8 = 720;
int pad_0_9 = 912;
int pad_0_10 = 620;
int pad_0_11 = 804;
int pad_0_12 = 694;
int pad_0_13 = 394;
int pad_0_14 = 766;
int pad_0_15 = 651;
int pad_0_16 = 727;
int pad_0_17 = 895;
int pad_0_18 = 501;
int pad_0_19 = 170;
int pad_0_20 = 713;
int pad_0_21 = 42;
int pad_0_22 = 60;
int pad_0_23 = 502;
int pad_0_24 = 68;
int pad_0_25 = 130;
int pad_0_26 = 113;
int pad_0_27 = 933;
int pad_0_28 = 10;
int pad_0_29 = 167;
int pad_0_30 = 468;
int pad_0_31 = 620;
int pad_0_32 = 922;
int pad_0_33 = 659;
int pad_0_34 = 357;
int pad_0_35 = 27;
int pad_0_36 = 340;
int pad_0_37 = 633;
int pad_0_38 = 470;
int pad_0_39 = 147;
int pad_0_40 = 907;
int pad_0_41 = 720;
int pad_0_42 = 221;
int pad_0_43 = 871;
int pad_0_44 = 421;
int pad_0_45 = 294;
int pad_0_46 = 287;
int pad_0_47 = 991;
int pad_0_48 = 387;
int pad_0_49 = 789;
int pad_0_50 = 251;
int pad_0_51 = 733;
int pad_0_52 = 863;
int pad_0_53 = 172;
int pad_0_54 = 365;
int pad_0_55 = 832;
int pad_0_56 = 750;
int pad_0_57 = 321;
int pad_0_58 = 376;
int pad_0_59 = 538;
int pad_0_60 = 457;
int pad_0_61 = 415;
int pad_0_62 = 310;
int pad_0_63 = 566;
int pad_0_64 = 432;
int pad_0_65 = 879;
int pad_0_66 = 188;
int pad_0_67 = 474;
int pad_0_68 = 658;
int pad_0_69 = 105;
int pad_0_70 = 998;
int pad_0_71 = 382;
int pad_0_72 = 119;
int pad_0_73 = 954;
int pad_0_74 = 634;
int pad_0_75 = 849;
int pad_0_76 = 697;
int pad_0_77 = 103;
