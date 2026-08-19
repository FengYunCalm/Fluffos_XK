// representative: nested loops and conditionals
int count_primes_6(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 6;
}
int sum_squares_6(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_6_0 = 55;
int pad_6_1 = 920;
int pad_6_2 = 673;
int pad_6_3 = 596;
int pad_6_4 = 493;
int pad_6_5 = 680;
int pad_6_6 = 72;
int pad_6_7 = 163;
int pad_6_8 = 984;
int pad_6_9 = 714;
int pad_6_10 = 793;
int pad_6_11 = 597;
int pad_6_12 = 974;
int pad_6_13 = 353;
int pad_6_14 = 495;
int pad_6_15 = 284;
int pad_6_16 = 953;
int pad_6_17 = 704;
int pad_6_18 = 151;
int pad_6_19 = 808;
int pad_6_20 = 998;
int pad_6_21 = 821;
int pad_6_22 = 537;
int pad_6_23 = 834;
int pad_6_24 = 109;
int pad_6_25 = 287;
int pad_6_26 = 216;
int pad_6_27 = 26;
int pad_6_28 = 146;
int pad_6_29 = 139;
int pad_6_30 = 272;
int pad_6_31 = 24;
int pad_6_32 = 685;
int pad_6_33 = 43;
int pad_6_34 = 79;
int pad_6_35 = 352;
int pad_6_36 = 984;
int pad_6_37 = 978;
int pad_6_38 = 604;
int pad_6_39 = 62;
int pad_6_40 = 428;
int pad_6_41 = 965;
int pad_6_42 = 576;
int pad_6_43 = 44;
int pad_6_44 = 382;
int pad_6_45 = 334;
int pad_6_46 = 408;
int pad_6_47 = 40;
int pad_6_48 = 613;
int pad_6_49 = 453;
int pad_6_50 = 93;
int pad_6_51 = 238;
int pad_6_52 = 875;
int pad_6_53 = 862;
int pad_6_54 = 56;
int pad_6_55 = 255;
int pad_6_56 = 654;
int pad_6_57 = 488;
int pad_6_58 = 217;
int pad_6_59 = 578;
int pad_6_60 = 4;
int pad_6_61 = 643;
int pad_6_62 = 761;
int pad_6_63 = 960;
int pad_6_64 = 211;
int pad_6_65 = 115;
int pad_6_66 = 391;
int pad_6_67 = 170;
int pad_6_68 = 475;
int pad_6_69 = 817;
int pad_6_70 = 418;
int pad_6_71 = 419;
int pad_6_72 = 954;
int pad_6_73 = 921;
int pad_6_74 = 224;
int pad_6_75 = 910;
int pad_6_76 = 713;
int pad_6_77 = 302;
int pad_6_78 = 224;
