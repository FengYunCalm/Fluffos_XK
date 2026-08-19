// representative: macro expansion
#define MAX_4(a, b) ((a) > (b) ? (a) : (b))
#define MIN_4(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_4(x) ((x) * (x))
#define CUBE_4(x) (SQUARE_4(x) * (x))
#define LIMIT_4 183
#define TWICE_4(x) (SQUARE_4(x) + SQUARE_4(x))
#define THRICE_4(x) (CUBE_4(x) + SQUARE_4(x) + (x))
#define CLAMP_4(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_4(a, b, c) ((a) + (b) + (c))
#define PROD3_4(a, b, c) ((a) * (b) * (c))

int use_macros_4(int a, int b) {
  int m = MAX_4(a, b);
  int s = SQUARE_4(m);
  s = TWICE_4(s);
  s = THRICE_4(s);
  s = CLAMP_4(s, 0, LIMIT_4);
  s = SUM3_4(s, MIN_4(a, b), PROD3_4(a, b, 2));
  if (s > LIMIT_4) s = LIMIT_4;
  return s;
}
int pad_4_0 = 777;
int pad_4_1 = 625;
int pad_4_2 = 294;
int pad_4_3 = 869;
int pad_4_4 = 640;
int pad_4_5 = 656;
int pad_4_6 = 746;
int pad_4_7 = 958;
int pad_4_8 = 509;
int pad_4_9 = 339;
int pad_4_10 = 757;
int pad_4_11 = 985;
int pad_4_12 = 561;
int pad_4_13 = 922;
int pad_4_14 = 441;
int pad_4_15 = 794;
int pad_4_16 = 269;
int pad_4_17 = 972;
int pad_4_18 = 616;
int pad_4_19 = 900;
int pad_4_20 = 375;
int pad_4_21 = 656;
int pad_4_22 = 247;
int pad_4_23 = 449;
int pad_4_24 = 737;
int pad_4_25 = 44;
int pad_4_26 = 136;
int pad_4_27 = 428;
int pad_4_28 = 374;
int pad_4_29 = 117;
int pad_4_30 = 654;
int pad_4_31 = 579;
int pad_4_32 = 81;
int pad_4_33 = 677;
int pad_4_34 = 16;
int pad_4_35 = 398;
int pad_4_36 = 489;
int pad_4_37 = 964;
int pad_4_38 = 353;
int pad_4_39 = 263;
int pad_4_40 = 477;
int pad_4_41 = 391;
int pad_4_42 = 745;
int pad_4_43 = 854;
int pad_4_44 = 376;
int pad_4_45 = 948;
int pad_4_46 = 403;
int pad_4_47 = 758;
int pad_4_48 = 324;
int pad_4_49 = 823;
int pad_4_50 = 736;
int pad_4_51 = 831;
int pad_4_52 = 623;
int pad_4_53 = 100;
int pad_4_54 = 714;
int pad_4_55 = 856;
int pad_4_56 = 242;
int pad_4_57 = 464;
int pad_4_58 = 934;
int pad_4_59 = 336;
int pad_4_60 = 692;
int pad_4_61 = 507;
int pad_4_62 = 941;
int pad_4_63 = 954;
int pad_4_64 = 219;
int pad_4_65 = 425;
int pad_4_66 = 851;
int pad_4_67 = 535;
int pad_4_68 = 541;
int pad_4_69 = 225;
int pad_4_70 = 945;
int pad_4_71 = 819;
int pad_4_72 = 411;
int pad_4_73 = 348;
int pad_4_74 = 659;
int pad_4_75 = 632;
int pad_4_76 = 709;
int pad_4_77 = 750;
