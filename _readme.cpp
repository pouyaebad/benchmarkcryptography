
#include "pch.h" 

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
/*                                2- nvcc 12.8 for CUDA                                                                           */
/*                                                                                                                                */
/*     Libraries & Dependencies:  1- CUDA                static linking    V 12.8                                                 */
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

/*

	Developed classes for this project:

		1-	AES_GCM
						Abstract polymorphic class, contains functions to write logs, loads test data file into buffer and so on

		2-	AES_GCM_IPP
						Inherited from AES_GCM and implements IPP implementation of AES-GCM

		3-	AES_GCM_CPU
						Inherited from AES_GCM and contains copies of AES_GCM_IMPL so it can run AES-GCM on CPU

		4-	AES_GCM_GPU
						Inherited from AES_GCM, runs CUDA kernel. CUDA kernel creates copies of AES_GCM_IMPL so it can run AES-GCM on GPU

		5-	AES_GCM_IMPL
						A concrete class, which implements mathematical algorithms of AES-GCM


		6-	SHA256
						A concrete class, which implements SHA256 hashing algorithm



		7-	System_Information
						A helper class to get machine’s hardware information

		8-	IPP_Features
						A helper class to get Intel IPP Lib’s information

		9-	CUDA_Features
						A helper class to get GPU’s hardware information



		10-	ECDSA256.cpp & ECDSA256.h (files)
						set of C type functions for ECDSA (P-256) signature verification

		11-	Common_defs.h (file)
						Common data types and definitions

		12-	Utility.h (file)
						Helper functions, mainly for string formatting also some other small functions
*/

/*
	Error Codes inside the Program:

		"Error #AGM-XX":  class AES_GCM
		"Error #AGC-XX":  class AES_GCM_CPU
		"Error #AGG-XX":  class AES_GCM_GPU
		"Error #AGI-XX":  class AES_GCM_IPP
		"Error #DBA-XX":  class CDialogPage_Bench_AES
		"Error #DBS-XX":  class CDialogPage_Bench_ECC_SHA
*/
