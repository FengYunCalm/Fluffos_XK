// representative: nested loops and conditionals
int count_primes_0(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 0;
}
int sum_squares_0(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_0_0 = 48;
int pad_0_1 = 21;
int pad_0_2 = 62;
int pad_0_3 = 329;
int pad_0_4 = 198;
int pad_0_5 = 19;
int pad_0_6 = 609;
int pad_0_7 = 623;
int pad_0_8 = 992;
int pad_0_9 = 508;
int pad_0_10 = 535;
int pad_0_11 = 611;
int pad_0_12 = 224;
int pad_0_13 = 665;
int pad_0_14 = 868;
int pad_0_15 = 693;
int pad_0_16 = 315;
int pad_0_17 = 594;
int pad_0_18 = 668;
int pad_0_19 = 750;
int pad_0_20 = 193;
int pad_0_21 = 33;
int pad_0_22 = 104;
int pad_0_23 = 397;
int pad_0_24 = 820;
int pad_0_25 = 975;
int pad_0_26 = 85;
int pad_0_27 = 732;
int pad_0_28 = 621;
int pad_0_29 = 906;
int pad_0_30 = 525;
int pad_0_31 = 293;
int pad_0_32 = 743;
int pad_0_33 = 662;
int pad_0_34 = 948;
int pad_0_35 = 866;
int pad_0_36 = 536;
int pad_0_37 = 809;
int pad_0_38 = 704;
int pad_0_39 = 525;
int pad_0_40 = 901;
int pad_0_41 = 436;
int pad_0_42 = 300;
int pad_0_43 = 713;
int pad_0_44 = 515;
int pad_0_45 = 572;
int pad_0_46 = 881;
int pad_0_47 = 139;
int pad_0_48 = 510;
int pad_0_49 = 58;
int pad_0_50 = 919;
int pad_0_51 = 11;
int pad_0_52 = 274;
int pad_0_53 = 709;
int pad_0_54 = 336;
int pad_0_55 = 819;
int pad_0_56 = 776;
int pad_0_57 = 639;
int pad_0_58 = 942;
int pad_0_59 = 450;
int pad_0_60 = 405;
int pad_0_61 = 528;
int pad_0_62 = 212;
int pad_0_63 = 547;
int pad_0_64 = 121;
int pad_0_65 = 632;
int pad_0_66 = 864;
int pad_0_67 = 839;
int pad_0_68 = 390;
int pad_0_69 = 609;
int pad_0_70 = 19;
int pad_0_71 = 140;
int pad_0_72 = 926;
int pad_0_73 = 906;
int pad_0_74 = 856;
int pad_0_75 = 289;
int pad_0_76 = 728;
int pad_0_77 = 902;
int pad_0_78 = 564;
