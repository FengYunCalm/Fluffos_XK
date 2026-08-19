// representative: nested loops and conditionals
int count_primes_3(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 3;
}
int sum_squares_3(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_3_0 = 624;
int pad_3_1 = 307;
int pad_3_2 = 779;
int pad_3_3 = 767;
int pad_3_4 = 347;
int pad_3_5 = 213;
int pad_3_6 = 920;
int pad_3_7 = 248;
int pad_3_8 = 694;
int pad_3_9 = 67;
int pad_3_10 = 901;
int pad_3_11 = 856;
int pad_3_12 = 127;
int pad_3_13 = 379;
int pad_3_14 = 463;
int pad_3_15 = 945;
int pad_3_16 = 826;
int pad_3_17 = 50;
int pad_3_18 = 289;
int pad_3_19 = 781;
int pad_3_20 = 842;
int pad_3_21 = 360;
int pad_3_22 = 209;
int pad_3_23 = 981;
int pad_3_24 = 664;
int pad_3_25 = 884;
int pad_3_26 = 592;
int pad_3_27 = 670;
int pad_3_28 = 968;
int pad_3_29 = 759;
int pad_3_30 = 150;
int pad_3_31 = 722;
int pad_3_32 = 724;
int pad_3_33 = 516;
int pad_3_34 = 381;
int pad_3_35 = 674;
int pad_3_36 = 410;
int pad_3_37 = 737;
int pad_3_38 = 583;
int pad_3_39 = 25;
int pad_3_40 = 530;
int pad_3_41 = 307;
int pad_3_42 = 425;
int pad_3_43 = 784;
int pad_3_44 = 198;
int pad_3_45 = 871;
int pad_3_46 = 186;
int pad_3_47 = 379;
int pad_3_48 = 184;
int pad_3_49 = 299;
int pad_3_50 = 327;
int pad_3_51 = 73;
int pad_3_52 = 279;
int pad_3_53 = 425;
int pad_3_54 = 801;
int pad_3_55 = 388;
int pad_3_56 = 660;
int pad_3_57 = 115;
int pad_3_58 = 70;
int pad_3_59 = 654;
int pad_3_60 = 31;
int pad_3_61 = 803;
int pad_3_62 = 255;
int pad_3_63 = 832;
int pad_3_64 = 219;
int pad_3_65 = 432;
int pad_3_66 = 103;
int pad_3_67 = 902;
int pad_3_68 = 562;
int pad_3_69 = 381;
int pad_3_70 = 791;
int pad_3_71 = 715;
int pad_3_72 = 116;
int pad_3_73 = 151;
int pad_3_74 = 930;
int pad_3_75 = 464;
int pad_3_76 = 896;
int pad_3_77 = 515;
int pad_3_78 = 272;
