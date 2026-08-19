// representative: nested loops and conditionals
int count_primes_1(int limit) {
  int count = 0;
  for (int i = 2; i < limit; i++) {
    int prime = 1;
    for (int j = 2; j * j <= i; j++) {
      if (i % j == 0) { prime = 0; break; }
    }
    if (prime) count++;
  }
  return count + 1;
}
int sum_squares_1(int n) {
  int total = 0;
  int i = 0;
  while (i < n) {
    total += i * i;
    i++;
  }
  return total;
}
int pad_1_0 = 295;
int pad_1_1 = 189;
int pad_1_2 = 150;
int pad_1_3 = 453;
int pad_1_4 = 901;
int pad_1_5 = 612;
int pad_1_6 = 768;
int pad_1_7 = 281;
int pad_1_8 = 84;
int pad_1_9 = 502;
int pad_1_10 = 21;
int pad_1_11 = 858;
int pad_1_12 = 199;
int pad_1_13 = 224;
int pad_1_14 = 431;
int pad_1_15 = 73;
int pad_1_16 = 251;
int pad_1_17 = 128;
int pad_1_18 = 863;
int pad_1_19 = 464;
int pad_1_20 = 20;
int pad_1_21 = 706;
int pad_1_22 = 121;
int pad_1_23 = 675;
int pad_1_24 = 637;
int pad_1_25 = 839;
int pad_1_26 = 675;
int pad_1_27 = 856;
int pad_1_28 = 91;
int pad_1_29 = 155;
int pad_1_30 = 782;
int pad_1_31 = 975;
int pad_1_32 = 878;
int pad_1_33 = 926;
int pad_1_34 = 905;
int pad_1_35 = 495;
int pad_1_36 = 109;
int pad_1_37 = 886;
int pad_1_38 = 42;
int pad_1_39 = 726;
int pad_1_40 = 828;
int pad_1_41 = 214;
int pad_1_42 = 173;
int pad_1_43 = 661;
int pad_1_44 = 739;
int pad_1_45 = 432;
int pad_1_46 = 820;
int pad_1_47 = 256;
int pad_1_48 = 186;
int pad_1_49 = 11;
int pad_1_50 = 158;
int pad_1_51 = 288;
int pad_1_52 = 927;
int pad_1_53 = 532;
int pad_1_54 = 710;
int pad_1_55 = 827;
int pad_1_56 = 407;
int pad_1_57 = 31;
int pad_1_58 = 948;
int pad_1_59 = 565;
int pad_1_60 = 757;
int pad_1_61 = 795;
int pad_1_62 = 776;
int pad_1_63 = 636;
int pad_1_64 = 37;
int pad_1_65 = 65;
int pad_1_66 = 983;
int pad_1_67 = 491;
int pad_1_68 = 640;
int pad_1_69 = 78;
int pad_1_70 = 845;
int pad_1_71 = 184;
int pad_1_72 = 118;
int pad_1_73 = 748;
int pad_1_74 = 977;
int pad_1_75 = 37;
int pad_1_76 = 852;
int pad_1_77 = 27;
int pad_1_78 = 72;
