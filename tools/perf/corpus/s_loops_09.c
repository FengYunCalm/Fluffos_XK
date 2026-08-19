// representative: nested loops and conditionals
int count_primes_9(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 9;
}
int sum_squares_9(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_9_0 = 886;
int pad_9_1 = 703;
int pad_9_2 = 546;
int pad_9_3 = 466;
int pad_9_4 = 280;
int pad_9_5 = 711;
int pad_9_6 = 412;
int pad_9_7 = 564;
int pad_9_8 = 970;
int pad_9_9 = 937;
int pad_9_10 = 118;
int pad_9_11 = 45;
int pad_9_12 = 575;
int pad_9_13 = 318;
int pad_9_14 = 645;
int pad_9_15 = 676;
int pad_9_16 = 747;
int pad_9_17 = 375;
int pad_9_18 = 863;
int pad_9_19 = 412;
int pad_9_20 = 843;
int pad_9_21 = 112;
int pad_9_22 = 510;
int pad_9_23 = 612;
int pad_9_24 = 894;
int pad_9_25 = 391;
int pad_9_26 = 273;
int pad_9_27 = 560;
int pad_9_28 = 637;
int pad_9_29 = 347;
int pad_9_30 = 393;
int pad_9_31 = 650;
int pad_9_32 = 210;
int pad_9_33 = 543;
int pad_9_34 = 353;
int pad_9_35 = 678;
int pad_9_36 = 909;
int pad_9_37 = 31;
int pad_9_38 = 87;
int pad_9_39 = 459;
int pad_9_40 = 716;
int pad_9_41 = 76;
int pad_9_42 = 575;
int pad_9_43 = 380;
int pad_9_44 = 169;
int pad_9_45 = 868;
int pad_9_46 = 808;
int pad_9_47 = 88;
int pad_9_48 = 883;
int pad_9_49 = 719;
int pad_9_50 = 318;
int pad_9_51 = 228;
int pad_9_52 = 828;
int pad_9_53 = 481;
int pad_9_54 = 839;
int pad_9_55 = 392;
int pad_9_56 = 465;
int pad_9_57 = 515;
int pad_9_58 = 336;
int pad_9_59 = 101;
int pad_9_60 = 99;
int pad_9_61 = 620;
int pad_9_62 = 141;
int pad_9_63 = 318;
int pad_9_64 = 160;
int pad_9_65 = 516;
int pad_9_66 = 543;
int pad_9_67 = 417;
int pad_9_68 = 313;
int pad_9_69 = 799;
int pad_9_70 = 352;
int pad_9_71 = 63;
int pad_9_72 = 413;
int pad_9_73 = 751;
int pad_9_74 = 798;
int pad_9_75 = 548;
int pad_9_76 = 7;
int pad_9_77 = 253;
int pad_9_78 = 352;
