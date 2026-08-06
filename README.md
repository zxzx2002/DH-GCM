# DH-GCM
Source code of DH-GCM (GLOBECOM 2026).
## Paper
DH-GCM: Offloading GCM Encryption to Programmable Data Planes
## Cite
Waiting for public search
## Abstract
As cyber threats continue to increase, encryption has become a key technology for securing network infrastructures. However, traditional host-based encryption faces severe throughput bottlenecks, while existing in-network encryption solutions are hindered by high hardware resource overhead and static key configuration, limiting their practical deployment. To address these limitations, this paper proposes DH-GCM, a data plane encryption scheme that achieves high throughput, low resource overhead, and flexible key configuration. Specifically, we offload the Galois Counter Mode (GCM) encryption algorithm to the data plane through hardware-friendly deployment and hash-based optimizations. A Diffie-Hellman key exchange algorithm is introduced to dynamically derive encryption keys, enabling flexible key configuration. Implemented on an Intel Tofino switch, DH-GCM improves system throughput by 6.27\%, reduces the average hardware resource overhead by 46.72\%, and achieves comparable key configuration latency with  state-of-the-art approaches, offering a viable path for deploying high-performance in-network encryption within the data plane.
## Source Code Usage
### Overview
We have provided four folders.
#### GCM16bit/ and GCM32bit/
It contains the P4 program for the data plane implementation of the GCM encryption algorithm with encryption lengths of 16 bits and 32 bits in the data plane respectively. All data plane operations are carried out within the Intel Tofino Switch Ingress.
#### GCM16bitegress/ and GCM32bitegress/
It contains the P4 program for the data plane implementation of the GCM encryption algorithm with encryption lengths of 16 bits and 32 bits in the data plane respectively. We carried out two rounds of GCM encryption, which were executed within switch Ingress and Egress respectively, demonstrating our potential for multi-round encryption. We can allow for recirculation within the switch and conduct more rounds of encryption.
### Setup Instructions   
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.
