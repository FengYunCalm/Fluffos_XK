// representative: nested loops and conditionals
int count_primes_4(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 4;
}
int sum_squares_4(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_4_0 = 65;
int pad_4_1 = 233;
int pad_4_2 = 907;
int pad_4_3 = 396;
int pad_4_4 = 731;
int pad_4_5 = 530;
int pad_4_6 = 636;
int pad_4_7 = 691;
int pad_4_8 = 521;
int pad_4_9 = 287;
int pad_4_10 = 348;
int pad_4_11 = 792;
int pad_4_12 = 843;
int pad_4_13 = 875;
int pad_4_14 = 664;
int pad_4_15 = 192;
int pad_4_16 = 531;
int pad_4_17 = 25;
int pad_4_18 = 325;
int pad_4_19 = 175;
int pad_4_20 = 455;
int pad_4_21 = 307;
int pad_4_22 = 539;
int pad_4_23 = 78;
int pad_4_24 = 459;
int pad_4_25 = 16;
int pad_4_26 = 914;
int pad_4_27 = 297;
int pad_4_28 = 922;
int pad_4_29 = 417;
int pad_4_30 = 49;
int pad_4_31 = 440;
int pad_4_32 = 248;
int pad_4_33 = 295;
int pad_4_34 = 861;
int pad_4_35 = 137;
int pad_4_36 = 165;
int pad_4_37 = 785;
int pad_4_38 = 263;
int pad_4_39 = 196;
int pad_4_40 = 774;
int pad_4_41 = 717;
int pad_4_42 = 291;
int pad_4_43 = 614;
int pad_4_44 = 112;
int pad_4_45 = 783;
int pad_4_46 = 717;
int pad_4_47 = 686;
int pad_4_48 = 22;
int pad_4_49 = 351;
int pad_4_50 = 466;
int pad_4_51 = 770;
int pad_4_52 = 273;
int pad_4_53 = 300;
int pad_4_54 = 498;
int pad_4_55 = 912;
int pad_4_56 = 458;
int pad_4_57 = 532;
int pad_4_58 = 922;
int pad_4_59 = 209;
int pad_4_60 = 586;
int pad_4_61 = 519;
int pad_4_62 = 576;
int pad_4_63 = 916;
int pad_4_64 = 667;
int pad_4_65 = 954;
int pad_4_66 = 964;
int pad_4_67 = 624;
int pad_4_68 = 711;
int pad_4_69 = 892;
int pad_4_70 = 275;
int pad_4_71 = 964;
int pad_4_72 = 649;
int pad_4_73 = 910;
int pad_4_74 = 53;
int pad_4_75 = 412;
int pad_4_76 = 359;
int pad_4_77 = 67;
int pad_4_78 = 464;
