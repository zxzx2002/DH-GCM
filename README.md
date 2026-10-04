# DH-GCM
Source code of FlexGCM.
## Paper
FlexGCM: High-Performance and Flexible GCM Encryption Offloading in Programmable Data Planes
## Cite

## Abstract
The Galois Counter Mode (GCM) is a standard authenticated encryption algorithm for network protocols (e.g., TLS 1.3 and MACsec). However, when running on host CPUs, GCM suffers from severe throughput bottlenecks as link rates escalate to 100~Gbps and beyond, failing to sustain line rate processing. In-network encryption using programmable data planes offers a promising alternative, yet existing schemes suffer from high hardware resource overhead and lack runtime key and parameter flexibility. In this paper, we propose FlexGCM, a framework that fully offloads the GCM encryption algorithm to the programmable data plane. Specifically, (1) FlexGCM decomposes GCM into a compact five‑stage pipeline that maps all operations to hardware‑friendly primitives. (2) A lightweight Diffie‑Hellman key exchange provides runtime key flexibility with security. (3) The gRPC cross-plane communication enables runtime configuration of encryption parameters (e.g., block length, and encryption round) without interrupting packet processing. We have implemented FlexGCM on an Intel Tofino switch. Experimental results show that FlexGCM improves throughput by 6.27\%, reduces average hardware resource overhead by 46.7\%, and achieves runtime parameter configuration with 1.03 ms, demonstrating high throughput, low resource overhead, and runtime flexibility.
## Source Code Usage
### Overview
We have provided four folders.
#### GCM16bit/ and GCM32bit/
It contains the P4 program for the data plane implementation of the GCM encryption algorithm with encryption lengths of 16 bits and 32 bits in the data plane respectively. All data plane operations are carried out within the Intel Tofino Switch Ingress.
#### GCM16bitegress/ and GCM32bitegress/
It contains the P4 program for the data plane implementation of the GCM encryption algorithm with encryption lengths of 16 bits and 32 bits in the data plane respectively. We carried out two rounds of GCM encryption, which were executed within switch Ingress and Egress respectively, demonstrating our potential for multi-round encryption. We can allow for recirculation within the switch and conduct more rounds of encryption.
### Setup Instructions   
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.
As for the control plane Python program, we utilize Python 3.8.
