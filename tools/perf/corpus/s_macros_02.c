// representative: macro expansion
#define MAX_2(a, b) ((a) > (b) ? (a) : (b))
#define MIN_2(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_2(x) ((x) * (x))
#define CUBE_2(x) (SQUARE_2(x) * (x))
#define LIMIT_2 491
#define TWICE_2(x) (SQUARE_2(x) + SQUARE_2(x))
#define THRICE_2(x) (CUBE_2(x) + SQUARE_2(x) + (x))
#define CLAMP_2(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_2(a, b, c) ((a) + (b) + (c))
#define PROD3_2(a, b, c) ((a) * (b) * (c))

int use_macros_2(int a, int b) {
  int m = MAX_2(a, b);
  int s = SQUARE_2(m);
  s = TWICE_2(s);
  s = THRICE_2(s);
  s = CLAMP_2(s, 0, LIMIT_2);
  s = SUM3_2(s, MIN_2(a, b), PROD3_2(a, b, 2));
  if (s > LIMIT_2) s = LIMIT_2;
  return s;
}
int pad_2_0 = 319;
int pad_2_1 = 810;
int pad_2_2 = 581;
int pad_2_3 = 945;
int pad_2_4 = 693;
int pad_2_5 = 435;
int pad_2_6 = 639;
int pad_2_7 = 756;
int pad_2_8 = 173;
int pad_2_9 = 849;
int pad_2_10 = 317;
int pad_2_11 = 798;
int pad_2_12 = 844;
int pad_2_13 = 334;
int pad_2_14 = 868;
int pad_2_15 = 643;
int pad_2_16 = 733;
int pad_2_17 = 659;
int pad_2_18 = 771;
int pad_2_19 = 347;
int pad_2_20 = 917;
int pad_2_21 = 690;
int pad_2_22 = 766;
int pad_2_23 = 711;
int pad_2_24 = 266;
int pad_2_25 = 56;
int pad_2_26 = 162;
int pad_2_27 = 372;
int pad_2_28 = 582;
int pad_2_29 = 932;
int pad_2_30 = 793;
int pad_2_31 = 437;
int pad_2_32 = 42;
int pad_2_33 = 773;
int pad_2_34 = 287;
int pad_2_35 = 648;
int pad_2_36 = 737;
int pad_2_37 = 167;
int pad_2_38 = 142;
int pad_2_39 = 733;
int pad_2_40 = 953;
int pad_2_41 = 524;
int pad_2_42 = 585;
int pad_2_43 = 177;
int pad_2_44 = 214;
int pad_2_45 = 978;
int pad_2_46 = 524;
int pad_2_47 = 18;
int pad_2_48 = 640;
int pad_2_49 = 777;
int pad_2_50 = 0;
int pad_2_51 = 55;
int pad_2_52 = 658;
int pad_2_53 = 604;
int pad_2_54 = 741;
int pad_2_55 = 967;
int pad_2_56 = 90;
int pad_2_57 = 230;
int pad_2_58 = 961;
int pad_2_59 = 632;
int pad_2_60 = 807;
int pad_2_61 = 299;
int pad_2_62 = 767;
int pad_2_63 = 654;
int pad_2_64 = 251;
int pad_2_65 = 683;
int pad_2_66 = 230;
int pad_2_67 = 334;
int pad_2_68 = 906;
int pad_2_69 = 129;
int pad_2_70 = 737;
int pad_2_71 = 259;
int pad_2_72 = 622;
int pad_2_73 = 947;
int pad_2_74 = 175;
int pad_2_75 = 190;
int pad_2_76 = 653;
int pad_2_77 = 23;
