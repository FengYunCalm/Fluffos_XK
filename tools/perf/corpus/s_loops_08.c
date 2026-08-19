// representative: nested loops and conditionals
int count_primes_8(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 8;
}
int sum_squares_8(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_8_0 = 899;
int pad_8_1 = 211;
int pad_8_2 = 546;
int pad_8_3 = 237;
int pad_8_4 = 127;
int pad_8_5 = 960;
int pad_8_6 = 598;
int pad_8_7 = 379;
int pad_8_8 = 533;
int pad_8_9 = 4;
int pad_8_10 = 447;
int pad_8_11 = 869;
int pad_8_12 = 69;
int pad_8_13 = 604;
int pad_8_14 = 405;
int pad_8_15 = 79;
int pad_8_16 = 504;
int pad_8_17 = 500;
int pad_8_18 = 368;
int pad_8_19 = 772;
int pad_8_20 = 892;
int pad_8_21 = 172;
int pad_8_22 = 257;
int pad_8_23 = 283;
int pad_8_24 = 764;
int pad_8_25 = 802;
int pad_8_26 = 555;
int pad_8_27 = 160;
int pad_8_28 = 846;
int pad_8_29 = 261;
int pad_8_30 = 415;
int pad_8_31 = 899;
int pad_8_32 = 844;
int pad_8_33 = 705;
int pad_8_34 = 447;
int pad_8_35 = 200;
int pad_8_36 = 736;
int pad_8_37 = 51;
int pad_8_38 = 624;
int pad_8_39 = 964;
int pad_8_40 = 223;
int pad_8_41 = 998;
int pad_8_42 = 99;
int pad_8_43 = 561;
int pad_8_44 = 762;
int pad_8_45 = 687;
int pad_8_46 = 560;
int pad_8_47 = 331;
int pad_8_48 = 815;
int pad_8_49 = 701;
int pad_8_50 = 275;
int pad_8_51 = 126;
int pad_8_52 = 647;
int pad_8_53 = 856;
int pad_8_54 = 862;
int pad_8_55 = 993;
int pad_8_56 = 375;
int pad_8_57 = 124;
int pad_8_58 = 341;
int pad_8_59 = 920;
int pad_8_60 = 908;
int pad_8_61 = 380;
int pad_8_62 = 598;
int pad_8_63 = 871;
int pad_8_64 = 764;
int pad_8_65 = 631;
int pad_8_66 = 681;
int pad_8_67 = 490;
int pad_8_68 = 346;
int pad_8_69 = 96;
int pad_8_70 = 309;
int pad_8_71 = 197;
int pad_8_72 = 20;
int pad_8_73 = 154;
int pad_8_74 = 815;
int pad_8_75 = 540;
int pad_8_76 = 59;
int pad_8_77 = 997;
int pad_8_78 = 969;
