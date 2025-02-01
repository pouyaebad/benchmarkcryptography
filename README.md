# EncryptionBenchmark

Welcome to the Benchmarking Technical Reports and Source Codes! This repository contains a comprehensive report and source code in C++17 for Benchmarking Performance of Running Symmetric and Asymmetric Cryptography Algorithms: AES-GCM 128, AES-GCM 256, ECC (ECDSA) and SHA-256. 
The Benchmarking is also done for running AES-GCM cryptography on CPU, GPU (CUDA) and using Intel IPP (part of oneAPI)

## Table of Contents
- Benchmarking Running Performance of 128-bit and 256-bit versions of AES-GCM
- Benchmarking Running Performance of AES-GCM & ESDSA (Digital Signature) and SHA-256 (Hashing)
- Comparing DLMS / COSEM Security Suits 0, 1 and 2
- Benchmarking Running of AES-GCM on CPU and GPU (CUDA)
- Benchmarking Running of AES-GCM on CPU and Intel IPP (oneAPI)
- Benchmarking Running of AES-GCM with Different Number of Threads (Scalability Test) on CPU & GPU
- Benchmarking Performance of Implementation Languages C, C++, C#, Java and Python 

## Introduction
Full source code of Benchmarking software as well as technical reports (results) are included to check running performance of symmetric and asymmetric cryptography on CPU, GPU and IPP (CPU)

## Installation
Open the code in Visual Studio 2022, Built it all and run it, preferably in release mode.

## Usage
The project is Visual Studio (2022) project, intended to run under MS Windows. The UI is developed by MFC and to run GPU parts of Code, CUDA 12.5 should be installed. To run IPP parts of code Intel oneAPI 2025.0 should be installed too.

## Examples
- AES-GCM 128, 192 and 256 bits
- ECDSA (Digital Signature – ECC)
- SHA-256 Hashing
- CUDA and IPP implementations of AES-GCM

## Documentation
Two technical reports are included in the repository, source & header file have comments as well. Please check _readme.cpp file

## Contributing
Contributions are welcome! 

## License
MIT license

