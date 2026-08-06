#include <tna.p4>
#include "include/headers.p4"
#include "include/parsers.p4"

#define NUM_COUNTERS 2
#define REG_VALUE 16
#define REG_VALUE2 32
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Register<bit<REG_VALUE>,bit<16>>(NUM_COUNTERS) counter_registers;
    RegisterAction<bit<REG_VALUE>, bit<16>, bit<16>>(counter_registers)action_counter_registers_update = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;//读取初始化寄存器
            }};
    Register<bit<REG_VALUE2>,bit<32>>(NUM_COUNTERS) counter_registers_comb;
    RegisterAction<bit<REG_VALUE2>, bit<32>, bit<32>>(counter_registers_comb)action_counter_registers_comb_update = {
        void apply(inout bit<32> gcm_comb, out bit<32> write_comb) {
            gcm_comb = meta.gcm_comb;
            write_comb = gcm_comb;
            }};//写入gcm_comb寄存器
    Register<bit<REG_VALUE2>,bit<32>>(NUM_COUNTERS) counter_registers_ciphertext;
    RegisterAction<bit<REG_VALUE2>, bit<32>, bit<32>>(counter_registers_ciphertext)action_counter_registers_ciphertext_update = {
        void apply(inout bit<32> ciphertext, out bit<32> write_ciphertext) {
            ciphertext = meta.ciphertext;
            write_ciphertext = ciphertext;
            }};//写入ciphertext寄存器

    CRCPolynomial<bit<32>>(32w0x04C11DB7, true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) hash_gcm;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) hash_gcm2;

/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/

    action calculate_gcm_h(){
        meta.gcm_h = hash_gcm.get(meta.zero_vector);//kth Hash多项式加密
    }
    action calculate_gcm_comb(){
        meta.gcm_comb = hash_gcm2.get(meta.comb) ;//hth Hash多项式加密
    }
    action calculate_gcm_p(){
        meta.gcm_p = hash_gcm2.get(meta.p) ;//模拟时，p为ipv4两个字段组合，gcm_p将p用hth Hash多项式加密
    }

    action combine(bit<16>read_value,bit<16>random_16bit){
        meta.comb[31:16] = random_16bit;
        meta.comb[15:0] = read_value;
    }
    action combine2(bit<16>read_value,bit<16>random_16bit){
        meta.p[31:16] = random_16bit;
        meta.p[15:0] = read_value;
    }
   action xor(){
        meta.ciphertext = meta.gcm_comb ^ meta.p;
    }
    action set_egress_port(egressSpec_t egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    
    Random<bit<16>>() rnd16;
    table forwarding{
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port;drop; NoAction;}
        size = 64;
        default_action = drop;
    }
    apply {
        if (hdr.myTunnel.isValid()) {
            hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
        } 
        meta.zero_vector = 0;
        bit<16> random_16bit = rnd16.get();
        calculate_gcm_h();
        meta.read_value= action_counter_registers_update.execute(0);
        combine(meta.read_value,random_16bit);
        combine2(hdr.ipv4.totalLen,hdr.ipv4.hdrChecksum);
        calculate_gcm_comb();
        xor();
        action_counter_registers_comb_update.execute(0);
        action_counter_registers_ciphertext_update.execute(0);
        forwarding.apply();
    }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
	inout metadata meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){
	apply{
	    if (hdr.myTunnel.isValid()) {
            hdr.myTunnel.eg_tstamp = eg_intr_md_from_prsr.global_tstamp;
        }
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;