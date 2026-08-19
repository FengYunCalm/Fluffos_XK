// representative: nested loops and conditionals
int count_primes_7(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 7;
}
int sum_squares_7(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_7_0 = 326;
int pad_7_1 = 21;
int pad_7_2 = 282;
int pad_7_3 = 426;
int pad_7_4 = 161;
int pad_7_5 = 178;
int pad_7_6 = 909;
int pad_7_7 = 613;
int pad_7_8 = 969;
int pad_7_9 = 925;
int pad_7_10 = 775;
int pad_7_11 = 843;
int pad_7_12 = 197;
int pad_7_13 = 321;
int pad_7_14 = 807;
int pad_7_15 = 81;
int pad_7_16 = 898;
int pad_7_17 = 302;
int pad_7_18 = 990;
int pad_7_19 = 74;
int pad_7_20 = 739;
int pad_7_21 = 205;
int pad_7_22 = 675;
int pad_7_23 = 662;
int pad_7_24 = 4;
int pad_7_25 = 503;
int pad_7_26 = 527;
int pad_7_27 = 379;
int pad_7_28 = 522;
int pad_7_29 = 68;
int pad_7_30 = 84;
int pad_7_31 = 11;
int pad_7_32 = 141;
int pad_7_33 = 169;
int pad_7_34 = 284;
int pad_7_35 = 400;
int pad_7_36 = 381;
int pad_7_37 = 230;
int pad_7_38 = 991;
int pad_7_39 = 696;
int pad_7_40 = 516;
int pad_7_41 = 730;
int pad_7_42 = 541;
int pad_7_43 = 292;
int pad_7_44 = 689;
int pad_7_45 = 932;
int pad_7_46 = 903;
int pad_7_47 = 625;
int pad_7_48 = 652;
int pad_7_49 = 462;
int pad_7_50 = 6;
int pad_7_51 = 189;
int pad_7_52 = 385;
int pad_7_53 = 653;
int pad_7_54 = 599;
int pad_7_55 = 480;
int pad_7_56 = 144;
int pad_7_57 = 135;
int pad_7_58 = 719;
int pad_7_59 = 549;
int pad_7_60 = 534;
int pad_7_61 = 361;
int pad_7_62 = 622;
int pad_7_63 = 69;
int pad_7_64 = 210;
int pad_7_65 = 550;
int pad_7_66 = 167;
int pad_7_67 = 55;
int pad_7_68 = 203;
int pad_7_69 = 914;
int pad_7_70 = 831;
int pad_7_71 = 312;
int pad_7_72 = 947;
int pad_7_73 = 889;
int pad_7_74 = 890;
int pad_7_75 = 769;
int pad_7_76 = 397;
int pad_7_77 = 433;
int pad_7_78 = 304;
