// representative: macro expansion
#define MAX_9(a, b) ((a) > (b) ? (a) : (b))
#define MIN_9(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_9(x) ((x) * (x))
#define CUBE_9(x) (SQUARE_9(x) * (x))
#define LIMIT_9 69
#define TWICE_9(x) (SQUARE_9(x) + SQUARE_9(x))
#define THRICE_9(x) (CUBE_9(x) + SQUARE_9(x) + (x))
#define CLAMP_9(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_9(a, b, c) ((a) + (b) + (c))
#define PROD3_9(a, b, c) ((a) * (b) * (c))

int use_macros_9(int a, int b) {
  int m = MAX_9(a, b);
  int s = SQUARE_9(m);
  s = TWICE_9(s);
  s = THRICE_9(s);
  s = CLAMP_9(s, 0, LIMIT_9);
  s = SUM3_9(s, MIN_9(a, b), PROD3_9(a, b, 2));
  if (s > LIMIT_9) s = LIMIT_9;
  return s;
}
int pad_9_0 = 625;
int pad_9_1 = 585;
int pad_9_2 = 994;
int pad_9_3 = 521;
int pad_9_4 = 59;
int pad_9_5 = 622;
int pad_9_6 = 441;
int pad_9_7 = 790;
int pad_9_8 = 581;
int pad_9_9 = 908;
int pad_9_10 = 757;
int pad_9_11 = 786;
int pad_9_12 = 507;
int pad_9_13 = 482;
int pad_9_14 = 34;
int pad_9_15 = 293;
int pad_9_16 = 151;
int pad_9_17 = 477;
int pad_9_18 = 971;
int pad_9_19 = 564;
int pad_9_20 = 483;
int pad_9_21 = 244;
int pad_9_22 = 759;
int pad_9_23 = 948;
int pad_9_24 = 766;
int pad_9_25 = 805;
int pad_9_26 = 875;
int pad_9_27 = 833;
int pad_9_28 = 17;
int pad_9_29 = 793;
int pad_9_30 = 540;
int pad_9_31 = 23;
int pad_9_32 = 39;
int pad_9_33 = 166;
int pad_9_34 = 294;
int pad_9_35 = 313;
int pad_9_36 = 211;
int pad_9_37 = 27;
int pad_9_38 = 863;
int pad_9_39 = 689;
int pad_9_40 = 10;
int pad_9_41 = 738;
int pad_9_42 = 752;
int pad_9_43 = 360;
int pad_9_44 = 713;
int pad_9_45 = 977;
int pad_9_46 = 610;
int pad_9_47 = 857;
int pad_9_48 = 424;
int pad_9_49 = 681;
int pad_9_50 = 765;
int pad_9_51 = 177;
int pad_9_52 = 179;
int pad_9_53 = 933;
int pad_9_54 = 781;
int pad_9_55 = 950;
int pad_9_56 = 158;
int pad_9_57 = 710;
int pad_9_58 = 958;
int pad_9_59 = 824;
int pad_9_60 = 226;
int pad_9_61 = 803;
int pad_9_62 = 510;
int pad_9_63 = 413;
int pad_9_64 = 189;
int pad_9_65 = 252;
int pad_9_66 = 79;
int pad_9_67 = 933;
int pad_9_68 = 50;
int pad_9_69 = 856;
int pad_9_70 = 841;
int pad_9_71 = 902;
int pad_9_72 = 32;
int pad_9_73 = 188;
int pad_9_74 = 50;
int pad_9_75 = 603;
int pad_9_76 = 30;
int pad_9_77 = 32;
