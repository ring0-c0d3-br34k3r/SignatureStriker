note from panji : do not use this code its just a bullshit its not complete, im not crazy to put complete code, this is an challenge for you, take this code and develop him more if u are a real Blue/Red Team

# SignatureStricker

## Disclaimer

This tool is designed to demonstrate how driver signature enforcement can be bypassed in a controlled environment. 

**DO NOT use this tool on production systems or any system where data integrity and security are paramount.** Disabling driver signature enforcement significantly weakens system security and makes it susceptible to malicious drivers.

## Description

signatureStricker is a tool written in C that disables driver signature enforcement for a specific driver installed on a Windows operating system. This is achieved by directly manipulating driver information obtained through the Windows API.

## Purpose

This tool serves as a resource for **cybersecurity blue teamers** seeking to:

* **Understand the risks associated with driver signature enforcement bypasses.**
* **Develop detection and mitigation strategies for such attacks.**
* **Analyze and improve driver security posture within their organization.**

## How it Works

1. **Enumerates Installed Drivers:** The tool uses the `SetupDiGetClassDevs` function to retrieve information about all installed devices and drivers.
2. **Identifies Target Driver:** It iterates through the driver list and searches for a specific driver name.
3. **Disables Signature Enforcement:** Upon finding the target driver, the tool uses a technique to disable its signature enforcement. This step varies depending on the specific method used by the tool. 

## Usage

Due to the inherent risks associated with this tool, **no usage instructions are provided**. Blue teamers are encouraged to analyze the code, understand its functionality, and adapt it for their specific research or educational purposes within a controlled and isolated environment.

## Contributing

We do not accept contributions or pull requests for this project. The code is provided "as is" for educational purposes. 

## Contact
telegram : @I0p17j8
