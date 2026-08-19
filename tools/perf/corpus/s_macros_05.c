// representative: macro expansion
#define MAX_5(a, b) ((a) > (b) ? (a) : (b))
#define MIN_5(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_5(x) ((x) * (x))
#define CUBE_5(x) (SQUARE_5(x) * (x))
#define LIMIT_5 191
#define TWICE_5(x) (SQUARE_5(x) + SQUARE_5(x))
#define THRICE_5(x) (CUBE_5(x) + SQUARE_5(x) + (x))
#define CLAMP_5(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_5(a, b, c) ((a) + (b) + (c))
#define PROD3_5(a, b, c) ((a) * (b) * (c))

int use_macros_5(int a, int b) {
  int m = MAX_5(a, b);
  int s = SQUARE_5(m);
  s = TWICE_5(s);
  s = THRICE_5(s);
  s = CLAMP_5(s, 0, LIMIT_5);
  s = SUM3_5(s, MIN_5(a, b), PROD3_5(a, b, 2));
  if (s > LIMIT_5) s = LIMIT_5;
  return s;
}
int pad_5_0 = 642;
int pad_5_1 = 750;
int pad_5_2 = 329;
int pad_5_3 = 164;
int pad_5_4 = 52;
int pad_5_5 = 772;
int pad_5_6 = 621;
int pad_5_7 = 100;
int pad_5_8 = 963;
int pad_5_9 = 248;
int pad_5_10 = 803;
int pad_5_11 = 941;
int pad_5_12 = 845;
int pad_5_13 = 150;
int pad_5_14 = 574;
int pad_5_15 = 555;
int pad_5_16 = 380;
int pad_5_17 = 694;
int pad_5_18 = 408;
int pad_5_19 = 836;
int pad_5_20 = 205;
int pad_5_21 = 836;
int pad_5_22 = 491;
int pad_5_23 = 787;
int pad_5_24 = 260;
int pad_5_25 = 227;
int pad_5_26 = 28;
int pad_5_27 = 378;
int pad_5_28 = 831;
int pad_5_29 = 370;
int pad_5_30 = 401;
int pad_5_31 = 756;
int pad_5_32 = 450;
int pad_5_33 = 834;
int pad_5_34 = 62;
int pad_5_35 = 277;
int pad_5_36 = 121;
int pad_5_37 = 9;
int pad_5_38 = 395;
int pad_5_39 = 489;
int pad_5_40 = 159;
int pad_5_41 = 132;
int pad_5_42 = 61;
int pad_5_43 = 474;
int pad_5_44 = 509;
int pad_5_45 = 692;
int pad_5_46 = 929;
int pad_5_47 = 528;
int pad_5_48 = 603;
int pad_5_49 = 618;
int pad_5_50 = 489;
int pad_5_51 = 980;
int pad_5_52 = 446;
int pad_5_53 = 865;
int pad_5_54 = 362;
int pad_5_55 = 197;
int pad_5_56 = 451;
int pad_5_57 = 423;
int pad_5_58 = 338;
int pad_5_59 = 75;
int pad_5_60 = 37;
int pad_5_61 = 682;
int pad_5_62 = 537;
int pad_5_63 = 102;
int pad_5_64 = 312;
int pad_5_65 = 882;
int pad_5_66 = 799;
int pad_5_67 = 493;
int pad_5_68 = 286;
int pad_5_69 = 982;
int pad_5_70 = 376;
int pad_5_71 = 198;
int pad_5_72 = 624;
int pad_5_73 = 859;
int pad_5_74 = 724;
int pad_5_75 = 734;
int pad_5_76 = 805;
int pad_5_77 = 465;
