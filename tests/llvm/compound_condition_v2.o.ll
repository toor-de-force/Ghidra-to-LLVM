; ModuleID = "lifted"
target triple = "unknown-unknown-unknown"
target datalayout = ""

@"RBP" = internal global i8* null
@"RSP" = internal global i8* null
@"RDI" = internal global i64 0
@"RIP" = internal global i8* null
@"CF" = internal global i1 0
@"OF" = internal global i1 0
@"SF" = internal global i1 0
@"ZF" = internal global i1 0
@"EAX" = internal global i32 0
@"RAX" = internal global i64 0
@"AL" = internal global i8 0
@"A_00101008:8" = internal global i64 0
@"A_00100000:8" = internal global i64 0
@"A_00101010:8" = internal global i64 0
@"A_0010006e:8" = internal global i64 0
@"A_00100026:8" = internal global i64 0
@"A_00100013:8" = internal global i64 0
define void @"path_start_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"() 
{
entry:
  %"stack" = alloca i8, i32 10485760
  %"stack_top" = getelementptr i8, i8* %"stack", i64 10485752
  store i8* %"stack_top", i8** @"RSP"
  br label %"00100000"
"00100000":
  %.5 = getelementptr i8, i8* null, i64 0
  %".4" = getelementptr i8, i8* null, i64 -8
  store i8* %".4", i8** @"RSP"
  %".6" = getelementptr i8*, i8** @"RSP", i64 0
  store i8* %".4", i8** %".6"
  br label %"00100001"
"00100001":
  %".9" = bitcast i8* %".5" to i8**
  %".10" = bitcast i8** @"RBP" to i8***
  store i8** %".9", i8*** %".10"
  br label %"00100004"
"00100004":
  %".13" = inttoptr i64 1048704 to i64*
  %".14" = bitcast i64* @"RDI" to i64**
  store i64* %".13", i64** %".14"
  br label %"0010000b"
"0010000b":
  %".17" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".17", i8** @"RSP"
  %".19" = getelementptr i8*, i8** @"RSP", i64 0
  %".20" = bitcast i8** %".19" to i64*
  store i64 1048592, i64* %".20"
  call void @"time_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"()
  br label %"00100010"
"00100010":
  br label %"00100011"
"00100011":
  %".25" = getelementptr i8, i8* %".5", i64 0
  %".26" = load i8, i8* %".25"
  %".27" = bitcast i8** @"RBP" to i8*
  store i8 %".26", i8* %".27"
  %".29" = getelementptr i8, i8* %".5", i64 8
  store i8* %".29", i8** @"RSP"
  br label %"00100012"
"00100012":
  %".32" = getelementptr i8, i8* %".5", i64 0
  %".33" = load i8, i8* %".32"
  %".34" = bitcast i8** @"RIP" to i8*
  store i8 %".33", i8* %".34"
  %".36" = getelementptr i8, i8* %".5", i64 8
  store i8* %".36", i8** @"RSP"
  ret void
}

define void @"path_goal_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"() 
{
entry:
  %"stack" = alloca i8, i32 10485760
  %"stack_top" = getelementptr i8, i8* %"stack", i64 10485752
  store i8* %"stack_top", i8** @"RSP"
  br label %"00100013"
"00100013":
  %".4" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".4", i8** @"RSP"
  %".6" = getelementptr i8*, i8** @"RSP", i64 0
  store i8* %".4", i8** %".6"
  br label %"00100014"
"00100014":
  %".9" = bitcast i8* %".5" to i8**
  %".10" = bitcast i8** @"RBP" to i8***
  store i8** %".9", i8*** %".10"
  br label %"00100017"
"00100017":
  %".13" = inttoptr i64 1048704 to i64*
  %".14" = bitcast i64* @"RDI" to i64**
  store i64* %".13", i64** %".14"
  br label %"0010001e"
"0010001e":
  %".17" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".17", i8** @"RSP"
  %".19" = getelementptr i8*, i8** @"RSP", i64 0
  %".20" = bitcast i8** %".19" to i64*
  store i64 1048611, i64* %".20"
  call void @"time_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"()
  br label %"00100023"
"00100023":
  br label %"00100024"
"00100024":
  %".25" = getelementptr i8, i8* %".5", i64 0
  %".26" = load i8, i8* %".25"
  %".27" = bitcast i8** @"RBP" to i8*
  store i8 %".26", i8* %".27"
  %".29" = getelementptr i8, i8* %".5", i64 8
  store i8* %".29", i8** @"RSP"
  br label %"00100025"
"00100025":
  %".32" = getelementptr i8, i8* %".5", i64 0
  %".33" = load i8, i8* %".32"
  %".34" = bitcast i8** @"RIP" to i8*
  store i8 %".33", i8* %".34"
  %".36" = getelementptr i8, i8* %".5", i64 8
  store i8* %".36", i8** @"RSP"
  ret void
}

define void @"path_nongoal_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"() 
{
entry:
  %"stack" = alloca i8, i32 10485760
  %"stack_top" = getelementptr i8, i8* %"stack", i64 10485752
  store i8* %"stack_top", i8** @"RSP"
  br label %"00100026"
"00100026":
  %".4" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".4", i8** @"RSP"
  %".6" = getelementptr i8*, i8** @"RSP", i64 0
  store i8* %".4", i8** %".6"
  br label %"00100027"
"00100027":
  %".9" = bitcast i8* %".5" to i8**
  %".10" = bitcast i8** @"RBP" to i8***
  store i8** %".9", i8*** %".10"
  br label %"0010002a"
"0010002a":
  %".13" = bitcast i64 1048704 to i64*
  %".14" = bitcast i64* @"RDI" to i64**
  store i64* %".13", i64** %".14"
  br label %"00100031"
"00100031":
  %".17" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".17", i8** @"RSP"
  %".19" = getelementptr i8*, i8** @"RSP", i64 0
  %".20" = bitcast i8** %".19" to i64*
  store i64 1048630, i64* %".20"
  call void @"time_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"()
  br label %"00100036"
"00100036":
  br label %"00100037"
"00100037":
  %".25" = getelementptr i8, i8* %".5", i64 0
  %".26" = load i8, i8* %".25"
  %".27" = bitcast i8** @"RBP" to i8*
  store i8 %".26", i8* %".27"
  %".29" = getelementptr i8, i8* %".5", i64 8
  store i8* %".29", i8** @"RSP"
  br label %"00100038"
"00100038":
  %".32" = getelementptr i8, i8* %".5", i64 0
  %".33" = load i8, i8* %".32"
  %".34" = bitcast i8** @"RIP" to i8*
  store i8 %".33", i8* %".34"
  %".36" = getelementptr i8, i8* %".5", i64 8
  store i8* %".36", i8** @"RSP"
  ret void
}

define void @"main_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"() 
{
entry:
  %"stack" = alloca i8, i32 10485760
  %"stack_top" = getelementptr i8, i8* %"stack", i64 10485752
  store i8* %"stack_top", i8** @"RSP"
  br label %"00100039"
"00100039":
  %".4" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".4", i8** @"RSP"
  %".6" = getelementptr i8*, i8** @"RSP", i64 0
  store i8* %".4", i8** %".6"
  br label %"0010003a"
"0010003a":
  %".9" = bitcast i8* %".5" to i8**
  %".10" = bitcast i8** @"RBP" to i8***
  store i8** %".9", i8*** %".10"
  br label %"0010003d"
"0010003d":
  %".13" = bitcast i8* %".5" to i64
  %".14" = icmp ult i64 %".13", 16
  store i1 %".14", i1* @"CF"
  %".16" = bitcast i8* %".5" to i64
  %".17" = getelementptr i8, i8* %".5", i64 -16
  store i8* %".17", i8** @"RSP"
  %".19" = bitcast i8* %".5" to i64
  %".20" = icmp slt i64 %".19", 0
  store i1 %".20", i1* @"SF"
  %".22" = bitcast i8* %".5" to i64
  %".23" = icmp eq i64 %".22", 0
  store i1 %".23", i1* @"ZF"
  br label %"00100041"
"00100041":
  %".26" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".26", i8** @"RSP"
  %".28" = getelementptr i8*, i8** @"RSP", i64 0
  %".29" = bitcast i8** %".28" to i64*
  store i64 1048646, i64* %".29"
  call void @"path_start_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"()
  br label %"00100046"
"00100046":
  %".33" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".33", i8** @"RSP"
  %".35" = getelementptr i8*, i8** @"RSP", i64 0
  %".36" = bitcast i8** %".35" to i64*
  store i64 1048651, i64* %".36"
  call void @"rand_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51"()
  br label %"0010004b"
"0010004b":
  %".40" = bitcast i8 0 to i1*
  %".41" = bitcast i1* @"CF" to i1**
  store i1* %".40", i1** %".41"
  %".43" = bitcast i8 0 to i1*
  %".44" = bitcast i1* @"OF" to i1**
  store i1* %".43", i1** %".44"
  %".46" = and i32 %".52", 65535
  store i32 %".46", i32* @"EAX"
  %".48" = zext i32 %".52" to i64
  store i64 %".48", i64* @"RAX"
  %".50" = icmp slt i32 %".52", 0
  store i1 %".50", i1* @"SF"
  %".52" = icmp eq i32 %".52", 0
  store i1 %".52", i1* @"ZF"
  br label %"00100050"
"00100050":
  %".55" = getelementptr i8, i8* %".4", i64 18446744073709551612
  %".56" = getelementptr i8, i8* %".55", i64 0
  %".57" = bitcast i8* %".56" to i32*
  store i32 %".52", i32* %".57"
  br label %"00100053"
"00100053":
  %".60" = getelementptr i8, i8* %".4", i64 18446744073709551612
  %".61" = bitcast i8* %".60" to i32
  %".62" = call {i32, i1} @"llvm.uadd.with.overflow.i32"(i32 %".61", i32 1)
  %".63" = extractvalue {i32, i1} %".62", 1
  store i1 %".63", i1* @"CF"
  %".65" = bitcast i8* %".60" to i32
  %".66" = call {i32, i1} @"llvm.sadd.with.overflow.i32"(i32 %".65", i32 1)
  %".67" = extractvalue {i32, i1} %".66", 1
  store i1 %".67", i1* @"OF"
  %".69" = bitcast i8* %".60" to i32
  %".70" = add i32 %".69", 1
  %".71" = getelementptr i8, i8* %".60", i64 0
  %".72" = bitcast i8* %".71" to i32*
  store i32 %".70", i32* %".72"
  %".74" = icmp slt i8* %".60", 0
  store i1 %".74", i1* @"SF"
  %".76" = icmp eq i8* %".60", 0
  store i1 %".76", i1* @"ZF"
  br label %"00100057"
"00100057":
  %".79" = getelementptr i8, i8* %".4", i64 18446744073709551612
  %".80" = bitcast i8* %".79" to i32*
  %".81" = bitcast i32* @"EAX" to i32**
  store i32* %".80", i32** %".81"
  %".83" = zext i32 %".52" to i64
  store i64 %".83", i64* @"RAX"
  br label %"0010005a"
"0010005a":
  %".86" = getelementptr i8, i8* %".4", i64 18446744073709551608
  %".87" = getelementptr i8, i8* %".86", i64 0
  %".88" = bitcast i8* %".87" to i32*
  store i32 %".52", i32* %".88"
  br label %"0010005d"
"0010005d":
  %".91" = getelementptr i8, i8* %".4", i64 18446744073709551608
  %".92" = bitcast i8* %".91" to i32*
  %".93" = bitcast i32* @"EAX" to i32**
  store i32* %".92", i32** %".93"
  %".95" = zext i32 %".52" to i64
  store i64 %".95", i64* @"RAX"
  br label %"00100060"
"00100060":
  %".98" = bitcast i8 0 to i1*
  %".99" = bitcast i1* @"CF" to i1**
  store i1* %".98", i1** %".99"
  %".101" = bitcast i8 0 to i1*
  %".102" = bitcast i1* @"OF" to i1**
  store i1* %".101", i1** %".102"
  %".104" = and i32 %".52", %".52"
  %".105" = icmp slt i32 %".104", 0
  store i1 %".105", i1* @"SF"
  %".107" = icmp eq i32 %".104", 0
  store i1 %".107", i1* @"ZF"
  br label %"00100062"
"00100062":
  %".110" = bitcast i1 %".74" to i8*
  %".111" = bitcast i8* @"AL" to i8**
  store i8* %".110", i8** %".111"
  br label %"00100065"
"00100065":
  %".114" = bitcast i8 0 to i1*
  %".115" = bitcast i1* @"CF" to i1**
  store i1* %".114", i1** %".115"
  %".117" = bitcast i8 0 to i1*
  %".118" = bitcast i1* @"OF" to i1**
  store i1* %".117", i1** %".118"
  %".120" = and i8 %".186", %".186"
  %".121" = icmp slt i8 %".120", 0
  store i1 %".121", i1* @"SF"
  %".123" = icmp eq i8 %".120", 0
  store i1 %".123", i1* @"ZF"
  br label %"00100067"
"00100067":
  br i1 %".74", label %"0010006e", label %"00100069"
"00100069":
  %".127" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".127", i8** @"RSP"
  %".129" = getelementptr i8*, i8** @"RSP", i64 0
  %".130" = bitcast i8** %".129" to i64*
  store i64 1048686, i64* %".130"
  call void @"path_nongoal_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"()
  br label %"0010006e"
"0010006e":
  %".134" = getelementptr i8, i8* %".5", i64 -8
  store i8* %".134", i8** @"RSP"
  %".136" = getelementptr i8*, i8** @"RSP", i64 0
  %".137" = bitcast i8** %".136" to i64*
  store i64 1048691, i64* %".137"
  call void @"path_goal_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"()
  br label %"00100073"
"00100073":
  %".141" = bitcast i64 0 to i64*
  %".142" = bitcast i64* @"RAX" to i64**
  store i64* %".141", i64** %".142"
  br label %"00100078"
"00100078":
  %".145" = bitcast i8* %".4" to i8**
  %".146" = bitcast i8** @"RSP" to i8***
  store i8** %".145", i8*** %".146"
  %".148" = getelementptr i8, i8* %".5", i64 0
  %".149" = load i8, i8* %".148"
  %".150" = bitcast i8** @"RBP" to i8*
  store i8 %".149", i8* %".150"
  %".152" = getelementptr i8, i8* %".5", i64 8
  store i8* %".152", i8** @"RSP"
  br label %"00100079"
"00100079":
  %".155" = getelementptr i8, i8* %".5", i64 0
  %".156" = load i8, i8* %".155"
  %".157" = bitcast i8** @"RIP" to i8*
  store i8 %".156", i8* %".157"
  %".159" = getelementptr i8, i8* %".5", i64 8
  store i8* %".159", i8** @"RSP"
  ret void
}

declare void @"time_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51_52_53_54_55_56_57_58"() 

declare void @"rand_0_1_2_3_4_5_6_7_8_9_10_11_12_13_14_15_16_17_18_19_20_21_22_23_24_25_26_27_28_29_30_31_32_33_34_35_36_37_38_39_40_41_42_43_44_45_46_47_48_49_50_51"() 

declare {i32, i1} @"llvm.uadd.with.overflow.i32"(i32 %".1", i32 %".2") 

declare {i32, i1} @"llvm.sadd.with.overflow.i32"(i32 %".1", i32 %".2") 
