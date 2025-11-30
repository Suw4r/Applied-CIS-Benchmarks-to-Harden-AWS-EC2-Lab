# CIS Ubuntu 24.04 CAT I Hardening on AWS EC2 lab

## Overview
This project demonstrates the application of CIS Ubuntu Linux 24.04 LTS STIG Benchmark benchmarks on an AWS EC2 instance. The aim of this project is to improve system security by applying hardening controls. This includes both automated and manual controls. For this project only CAT I benchmarks will be applied, which are of the highest severity. 

## Environment
- AWS EC2
- Ubuntu 24.04 EC2 instance
- CAT I controls only
- Manual verification where applicable
- The system contains only a root account. No additional local users or service accounts exist.
- Limitations: Rules requiring Ubuntu Pro subscription were not implemented, single user environment.

## Tools used
- AWS EC2
- Linux terminal via SSH
- CIS benchmark pdf
  
## Methodology
1. Read CIS CAT I benchmark PDF.
2. Apply applicable rules on the EC2 instance where possible.
3. Documented compliance with screenshots and notes.

## Findings
- Compliant: 9 rules
- Manual: 2 rules
- Not Applicable: 3 rules
- Not Implemented: 1 rule (Ubuntu Pro subscription required)
