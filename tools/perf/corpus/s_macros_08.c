// representative: macro expansion
#define MAX_8(a, b) ((a) > (b) ? (a) : (b))
#define MIN_8(a, b) ((a) < (b) ? (a) : (b))
#define SQUARE_8(x) ((x) * (x))
#define CUBE_8(x) (SQUARE_8(x) * (x))
#define LIMIT_8 88
#define TWICE_8(x) (SQUARE_8(x) + SQUARE_8(x))
#define THRICE_8(x) (CUBE_8(x) + SQUARE_8(x) + (x))
#define CLAMP_8(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define SUM3_8(a, b, c) ((a) + (b) + (c))
#define PROD3_8(a, b, c) ((a) * (b) * (c))

int use_macros_8(int a, int b) {
  int m = MAX_8(a, b);
  int s = SQUARE_8(m);
  s = TWICE_8(s);
  s = THRICE_8(s);
  s = CLAMP_8(s, 0, LIMIT_8);
  s = SUM3_8(s, MIN_8(a, b), PROD3_8(a, b, 2));
  if (s > LIMIT_8) s = LIMIT_8;
  return s;
}
int pad_8_0 = 476;
int pad_8_1 = 99;
int pad_8_2 = 914;
int pad_8_3 = 539;
int pad_8_4 = 429;
int pad_8_5 = 598;
int pad_8_6 = 3;
int pad_8_7 = 151;
int pad_8_8 = 886;
int pad_8_9 = 4;
int pad_8_10 = 840;
int pad_8_11 = 224;
int pad_8_12 = 749;
int pad_8_13 = 85;
int pad_8_14 = 481;
int pad_8_15 = 227;
int pad_8_16 = 922;
int pad_8_17 = 916;
int pad_8_18 = 422;
int pad_8_19 = 320;
int pad_8_20 = 89;
int pad_8_21 = 150;
int pad_8_22 = 765;
int pad_8_23 = 842;
int pad_8_24 = 468;
int pad_8_25 = 821;
int pad_8_26 = 711;
int pad_8_27 = 957;
int pad_8_28 = 179;
int pad_8_29 = 614;
int pad_8_30 = 161;
int pad_8_31 = 949;
int pad_8_32 = 95;
int pad_8_33 = 913;
int pad_8_34 = 786;
int pad_8_35 = 452;
int pad_8_36 = 378;
int pad_8_37 = 618;
int pad_8_38 = 958;
int pad_8_39 = 516;
int pad_8_40 = 683;
int pad_8_41 = 839;
int pad_8_42 = 990;
int pad_8_43 = 130;
int pad_8_44 = 767;
int pad_8_45 = 945;
int pad_8_46 = 645;
int pad_8_47 = 554;
int pad_8_48 = 782;
int pad_8_49 = 53;
int pad_8_50 = 710;
int pad_8_51 = 825;
int pad_8_52 = 206;
int pad_8_53 = 671;
int pad_8_54 = 354;
int pad_8_55 = 250;
int pad_8_56 = 616;
int pad_8_57 = 524;
int pad_8_58 = 193;
int pad_8_59 = 130;
int pad_8_60 = 869;
int pad_8_61 = 71;
int pad_8_62 = 561;
int pad_8_63 = 905;
int pad_8_64 = 516;
int pad_8_65 = 147;
int pad_8_66 = 231;
int pad_8_67 = 385;
int pad_8_68 = 806;
int pad_8_69 = 100;
int pad_8_70 = 317;
int pad_8_71 = 336;
int pad_8_72 = 11;
int pad_8_73 = 556;
int pad_8_74 = 19;
int pad_8_75 = 392;
int pad_8_76 = 83;
int pad_8_77 = 94;
