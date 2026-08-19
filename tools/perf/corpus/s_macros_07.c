// representative: macro expansion
#define MAX_7(a, b) ((a) > (b) ? (a) : (b))
#define MIN_7(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_7(x) ((x) * (x))
#define CUBE_7(x) (SQUARE_7(x) * (x))
#define LIMIT_7 254
#define TWICE_7(x) (SQUARE_7(x) + SQUARE_7(x))
#define THRICE_7(x) (CUBE_7(x) + SQUARE_7(x) + (x))
#define CLAMP_7(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_7(a, b, c) ((a) + (b) + (c))
#define PROD3_7(a, b, c) ((a) * (b) * (c))

int use_macros_7(int a, int b) {
  int m = MAX_7(a, b);
  int s = SQUARE_7(m);
  s = TWICE_7(s);
  s = THRICE_7(s);
  s = CLAMP_7(s, 0, LIMIT_7);
  s = SUM3_7(s, MIN_7(a, b), PROD3_7(a, b, 2));
  if (s > LIMIT_7) s = LIMIT_7;
  return s;
}
int pad_7_0 = 454;
int pad_7_1 = 277;
int pad_7_2 = 650;
int pad_7_3 = 901;
int pad_7_4 = 178;
int pad_7_5 = 395;
int pad_7_6 = 777;
int pad_7_7 = 603;
int pad_7_8 = 94;
int pad_7_9 = 191;
int pad_7_10 = 137;
int pad_7_11 = 27;
int pad_7_12 = 635;
int pad_7_13 = 425;
int pad_7_14 = 247;
int pad_7_15 = 210;
int pad_7_16 = 998;
int pad_7_17 = 596;
int pad_7_18 = 856;
int pad_7_19 = 194;
int pad_7_20 = 373;
int pad_7_21 = 856;
int pad_7_22 = 35;
int pad_7_23 = 882;
int pad_7_24 = 446;
int pad_7_25 = 807;
int pad_7_26 = 55;
int pad_7_27 = 133;
int pad_7_28 = 366;
int pad_7_29 = 24;
int pad_7_30 = 291;
int pad_7_31 = 672;
int pad_7_32 = 80;
int pad_7_33 = 764;
int pad_7_34 = 978;
int pad_7_35 = 906;
int pad_7_36 = 312;
int pad_7_37 = 620;
int pad_7_38 = 224;
int pad_7_39 = 669;
int pad_7_40 = 346;
int pad_7_41 = 64;
int pad_7_42 = 713;
int pad_7_43 = 717;
int pad_7_44 = 802;
int pad_7_45 = 301;
int pad_7_46 = 225;
int pad_7_47 = 8;
int pad_7_48 = 455;
int pad_7_49 = 729;
int pad_7_50 = 553;
int pad_7_51 = 910;
int pad_7_52 = 969;
int pad_7_53 = 829;
int pad_7_54 = 271;
int pad_7_55 = 844;
int pad_7_56 = 647;
int pad_7_57 = 469;
int pad_7_58 = 990;
int pad_7_59 = 357;
int pad_7_60 = 52;
int pad_7_61 = 666;
int pad_7_62 = 544;
int pad_7_63 = 331;
int pad_7_64 = 910;
int pad_7_65 = 834;
int pad_7_66 = 183;
int pad_7_67 = 956;
int pad_7_68 = 666;
int pad_7_69 = 104;
int pad_7_70 = 413;
int pad_7_71 = 392;
int pad_7_72 = 742;
int pad_7_73 = 587;
int pad_7_74 = 921;
int pad_7_75 = 44;
int pad_7_76 = 246;
int pad_7_77 = 594;
