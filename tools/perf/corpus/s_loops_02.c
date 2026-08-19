// representative: nested loops and conditionals
int count_primes_2(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 2;
}
int sum_squares_2(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_2_0 = 352;
int pad_2_1 = 733;
int pad_2_2 = 704;
int pad_2_3 = 786;
int pad_2_4 = 763;
int pad_2_5 = 817;
int pad_2_6 = 621;
int pad_2_7 = 610;
int pad_2_8 = 710;
int pad_2_9 = 697;
int pad_2_10 = 494;
int pad_2_11 = 457;
int pad_2_12 = 842;
int pad_2_13 = 672;
int pad_2_14 = 775;
int pad_2_15 = 201;
int pad_2_16 = 974;
int pad_2_17 = 603;
int pad_2_18 = 439;
int pad_2_19 = 312;
int pad_2_20 = 51;
int pad_2_21 = 804;
int pad_2_22 = 654;
int pad_2_23 = 27;
int pad_2_24 = 73;
int pad_2_25 = 653;
int pad_2_26 = 896;
int pad_2_27 = 62;
int pad_2_28 = 981;
int pad_2_29 = 968;
int pad_2_30 = 187;
int pad_2_31 = 570;
int pad_2_32 = 1000;
int pad_2_33 = 54;
int pad_2_34 = 942;
int pad_2_35 = 419;
int pad_2_36 = 291;
int pad_2_37 = 264;
int pad_2_38 = 683;
int pad_2_39 = 47;
int pad_2_40 = 380;
int pad_2_41 = 943;
int pad_2_42 = 716;
int pad_2_43 = 92;
int pad_2_44 = 304;
int pad_2_45 = 554;
int pad_2_46 = 658;
int pad_2_47 = 487;
int pad_2_48 = 509;
int pad_2_49 = 48;
int pad_2_50 = 583;
int pad_2_51 = 263;
int pad_2_52 = 165;
int pad_2_53 = 697;
int pad_2_54 = 184;
int pad_2_55 = 635;
int pad_2_56 = 87;
int pad_2_57 = 245;
int pad_2_58 = 975;
int pad_2_59 = 98;
int pad_2_60 = 866;
int pad_2_61 = 993;
int pad_2_62 = 29;
int pad_2_63 = 163;
int pad_2_64 = 828;
int pad_2_65 = 618;
int pad_2_66 = 890;
int pad_2_67 = 36;
int pad_2_68 = 979;
int pad_2_69 = 637;
int pad_2_70 = 400;
int pad_2_71 = 246;
int pad_2_72 = 578;
int pad_2_73 = 587;
int pad_2_74 = 945;
int pad_2_75 = 119;
int pad_2_76 = 618;
int pad_2_77 = 644;
int pad_2_78 = 23;
