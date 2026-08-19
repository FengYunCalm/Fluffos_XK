// representative: macro expansion
#define MAX_6(a, b) ((a) > (b) ? (a) : (b))
#define MIN_6(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_6(x) ((x) * (x))
#define CUBE_6(x) (SQUARE_6(x) * (x))
#define LIMIT_6 139
#define TWICE_6(x) (SQUARE_6(x) + SQUARE_6(x))
#define THRICE_6(x) (CUBE_6(x) + SQUARE_6(x) + (x))
#define CLAMP_6(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_6(a, b, c) ((a) + (b) + (c))
#define PROD3_6(a, b, c) ((a) * (b) * (c))

int use_macros_6(int a, int b) {
  int m = MAX_6(a, b);
  int s = SQUARE_6(m);
  s = TWICE_6(s);
  s = THRICE_6(s);
  s = CLAMP_6(s, 0, LIMIT_6);
  s = SUM3_6(s, MIN_6(a, b), PROD3_6(a, b, 2));
  if (s > LIMIT_6) s = LIMIT_6;
  return s;
}
int pad_6_0 = 852;
int pad_6_1 = 785;
int pad_6_2 = 840;
int pad_6_3 = 508;
int pad_6_4 = 796;
int pad_6_5 = 972;
int pad_6_6 = 107;
int pad_6_7 = 935;
int pad_6_8 = 563;
int pad_6_9 = 425;
int pad_6_10 = 700;
int pad_6_11 = 26;
int pad_6_12 = 61;
int pad_6_13 = 52;
int pad_6_14 = 326;
int pad_6_15 = 972;
int pad_6_16 = 454;
int pad_6_17 = 383;
int pad_6_18 = 241;
int pad_6_19 = 972;
int pad_6_20 = 930;
int pad_6_21 = 384;
int pad_6_22 = 253;
int pad_6_23 = 268;
int pad_6_24 = 950;
int pad_6_25 = 904;
int pad_6_26 = 186;
int pad_6_27 = 487;
int pad_6_28 = 300;
int pad_6_29 = 832;
int pad_6_30 = 895;
int pad_6_31 = 313;
int pad_6_32 = 875;
int pad_6_33 = 235;
int pad_6_34 = 92;
int pad_6_35 = 950;
int pad_6_36 = 651;
int pad_6_37 = 237;
int pad_6_38 = 169;
int pad_6_39 = 205;
int pad_6_40 = 323;
int pad_6_41 = 363;
int pad_6_42 = 454;
int pad_6_43 = 425;
int pad_6_44 = 259;
int pad_6_45 = 901;
int pad_6_46 = 94;
int pad_6_47 = 125;
int pad_6_48 = 632;
int pad_6_49 = 498;
int pad_6_50 = 595;
int pad_6_51 = 484;
int pad_6_52 = 355;
int pad_6_53 = 94;
int pad_6_54 = 375;
int pad_6_55 = 683;
int pad_6_56 = 845;
int pad_6_57 = 563;
int pad_6_58 = 483;
int pad_6_59 = 447;
int pad_6_60 = 149;
int pad_6_61 = 1000;
int pad_6_62 = 43;
int pad_6_63 = 642;
int pad_6_64 = 263;
int pad_6_65 = 22;
int pad_6_66 = 761;
int pad_6_67 = 533;
int pad_6_68 = 505;
int pad_6_69 = 383;
int pad_6_70 = 538;
int pad_6_71 = 560;
int pad_6_72 = 237;
int pad_6_73 = 452;
int pad_6_74 = 955;
int pad_6_75 = 513;
int pad_6_76 = 875;
int pad_6_77 = 681;
