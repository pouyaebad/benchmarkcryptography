# EncryptionBenchmark
/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                                                                                                */
/*     Project:                  Benchmarking Cryptography Algorithms Performance                                                 */
/*                                                                                                                                */
/*     Objectives:               1- Benchmarking Symmetric, Asymmetric (& Hashing) Encryption Algorithms                          */
/*                               2- Benchmarking CPU & GPU Performance for Cryptographic Operations                               */
/*                               3- Benchmarking Intel oneAPI IPP Library Performance vs Standard Execution Code for Cryptography */
/*                                                                                                                                */
/*     License:                  MIT for the codes I developed, some files (*.h, *.cpp, *.cuh) copied from other GitHub projects  */
/*                                                              Check inside each file about the licence & authors of the file    */
/*                                                                                                                                */
/*     Developed By:              Pouya Ebadollahyvahed                                                                           */
/*                                                                                                                                */
/*     First Development:         12 July 2024                                                                                    */
/*                                                                                                                                */
/*     Language:                  C++17                                                                                           */
/*                                                                                                                                */
/*     Target Platform:           Windows x64                                                                                     */
/*                                                                                                                                */
/*     Compiler:                  1- MSVC - Visual Studio 2022 V17.12.4                                                           */
/*                                2- nvcc 12.5 for CUDA                                                                           */
/*                                                                                                                                */
/*     Libraries & Dependencies:  1- CUDA                static linking    V 12.5                                                 */
/*                                2- Intel oneAPI IPP    static linking    V 12.0 (oneAPI 2025.0)                                 */
/*                                3- MFC                 static linking                                                           */
/*                                                                                                                                */
/*                                                                                                                                */
/*     Implemented Algorithms:    1- ECDSA    256 bit  ECC (Curve: secp256r1)  as per DLMS / COSEM Suite 1                        */
/*                                2- AES-GCM  128 bit, 192 bit and 256 bit     as per DLMS / COSEM Suite 0 & 2                    */
/*                                3- SHA      256 bit                          as per DLMS / COSEM Suite 0                        */
/*                                                                                                                                */
/*                                                                                                                                */
/**********************************************************************************************************************************/
