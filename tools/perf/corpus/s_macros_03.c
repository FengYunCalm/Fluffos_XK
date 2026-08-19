// representative: macro expansion
#define MAX_3(a, b) ((a) > (b) ? (a) : (b))
#define MIN_3(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_3(x) ((x) * (x))
#define CUBE_3(x) (SQUARE_3(x) * (x))
#define LIMIT_3 498
#define TWICE_3(x) (SQUARE_3(x) + SQUARE_3(x))
#define THRICE_3(x) (CUBE_3(x) + SQUARE_3(x) + (x))
#define CLAMP_3(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_3(a, b, c) ((a) + (b) + (c))
#define PROD3_3(a, b, c) ((a) * (b) * (c))

int use_macros_3(int a, int b) {
  int m = MAX_3(a, b);
  int s = SQUARE_3(m);
  s = TWICE_3(s);
  s = THRICE_3(s);
  s = CLAMP_3(s, 0, LIMIT_3);
  s = SUM3_3(s, MIN_3(a, b), PROD3_3(a, b, 2));
  if (s > LIMIT_3) s = LIMIT_3;
  return s;
}
int pad_3_0 = 122;
int pad_3_1 = 613;
int pad_3_2 = 769;
int pad_3_3 = 101;
int pad_3_4 = 11;
int pad_3_5 = 963;
int pad_3_6 = 184;
int pad_3_7 = 235;
int pad_3_8 = 151;
int pad_3_9 = 74;
int pad_3_10 = 356;
int pad_3_11 = 619;
int pad_3_12 = 133;
int pad_3_13 = 507;
int pad_3_14 = 738;
int pad_3_15 = 642;
int pad_3_16 = 249;
int pad_3_17 = 899;
int pad_3_18 = 47;
int pad_3_19 = 393;
int pad_3_20 = 405;
int pad_3_21 = 888;
int pad_3_22 = 758;
int pad_3_23 = 466;
int pad_3_24 = 81;
int pad_3_25 = 819;
int pad_3_26 = 148;
int pad_3_27 = 935;
int pad_3_28 = 636;
int pad_3_29 = 225;
int pad_3_30 = 683;
int pad_3_31 = 445;
int pad_3_32 = 94;
int pad_3_33 = 182;
int pad_3_34 = 221;
int pad_3_35 = 856;
int pad_3_36 = 429;
int pad_3_37 = 701;
int pad_3_38 = 908;
int pad_3_39 = 924;
int pad_3_40 = 278;
int pad_3_41 = 191;
int pad_3_42 = 868;
int pad_3_43 = 546;
int pad_3_44 = 206;
int pad_3_45 = 791;
int pad_3_46 = 963;
int pad_3_47 = 792;
int pad_3_48 = 79;
int pad_3_49 = 415;
int pad_3_50 = 168;
int pad_3_51 = 926;
int pad_3_52 = 676;
int pad_3_53 = 552;
int pad_3_54 = 307;
int pad_3_55 = 483;
int pad_3_56 = 104;
int pad_3_57 = 950;
int pad_3_58 = 207;
int pad_3_59 = 569;
int pad_3_60 = 684;
int pad_3_61 = 835;
int pad_3_62 = 191;
int pad_3_63 = 83;
int pad_3_64 = 533;
int pad_3_65 = 169;
int pad_3_66 = 243;
int pad_3_67 = 925;
int pad_3_68 = 194;
int pad_3_69 = 367;
int pad_3_70 = 660;
int pad_3_71 = 213;
int pad_3_72 = 624;
int pad_3_73 = 242;
int pad_3_74 = 229;
int pad_3_75 = 530;
int pad_3_76 = 273;
int pad_3_77 = 350;
