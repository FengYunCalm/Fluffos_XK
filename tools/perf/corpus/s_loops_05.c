// representative: nested loops and conditionals
int count_primes_5(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 5;
}
int sum_squares_5(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_5_0 = 132;
int pad_5_1 = 263;
int pad_5_2 = 125;
int pad_5_3 = 185;
int pad_5_4 = 845;
int pad_5_5 = 272;
int pad_5_6 = 379;
int pad_5_7 = 611;
int pad_5_8 = 617;
int pad_5_9 = 247;
int pad_5_10 = 958;
int pad_5_11 = 69;
int pad_5_12 = 821;
int pad_5_13 = 103;
int pad_5_14 = 536;
int pad_5_15 = 325;
int pad_5_16 = 171;
int pad_5_17 = 578;
int pad_5_18 = 821;
int pad_5_19 = 97;
int pad_5_20 = 569;
int pad_5_21 = 598;
int pad_5_22 = 362;
int pad_5_23 = 748;
int pad_5_24 = 148;
int pad_5_25 = 327;
int pad_5_26 = 345;
int pad_5_27 = 350;
int pad_5_28 = 529;
int pad_5_29 = 575;
int pad_5_30 = 213;
int pad_5_31 = 817;
int pad_5_32 = 861;
int pad_5_33 = 398;
int pad_5_34 = 151;
int pad_5_35 = 173;
int pad_5_36 = 65;
int pad_5_37 = 665;
int pad_5_38 = 748;
int pad_5_39 = 351;
int pad_5_40 = 739;
int pad_5_41 = 291;
int pad_5_42 = 478;
int pad_5_43 = 777;
int pad_5_44 = 914;
int pad_5_45 = 554;
int pad_5_46 = 423;
int pad_5_47 = 615;
int pad_5_48 = 395;
int pad_5_49 = 168;
int pad_5_50 = 583;
int pad_5_51 = 95;
int pad_5_52 = 832;
int pad_5_53 = 186;
int pad_5_54 = 989;
int pad_5_55 = 945;
int pad_5_56 = 572;
int pad_5_57 = 691;
int pad_5_58 = 308;
int pad_5_59 = 279;
int pad_5_60 = 253;
int pad_5_61 = 957;
int pad_5_62 = 994;
int pad_5_63 = 697;
int pad_5_64 = 741;
int pad_5_65 = 399;
int pad_5_66 = 21;
int pad_5_67 = 987;
int pad_5_68 = 603;
int pad_5_69 = 972;
int pad_5_70 = 545;
int pad_5_71 = 901;
int pad_5_72 = 146;
int pad_5_73 = 311;
int pad_5_74 = 712;
int pad_5_75 = 632;
int pad_5_76 = 572;
int pad_5_77 = 170;
int pad_5_78 = 407;
