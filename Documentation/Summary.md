# Summary

The Purpose of this project was to demonstrate how to implement NIST/CIS Benchmarks to harden an AWS EC2 lab. The newest Ubuntu CIS benchmark steps were followed with focus lying on applying the highest severity (CAT I) controls since those are the most 
critical, reducing security risks and following industry standard guidelines for system hardening.

The project began with the set up of an AWS EC2 instance with an Ubuntu server. SSH access was used to connect to this instance. Each CAT I control was handled following a standard of verification, remediation and result.
Actions that were taken include:
- Enabled SSH
- Ensured SSH was configured correctly
- Initialized OS requirement for a password for authentication upon booting into single-user and maintenance modes.
- The Ctrl-Alt-Del sequence has been disabled to help prevent accidental system reboots
- Disabled X11 display server since it can be exposed to attacks such as keystroke monitoring.
- Ensured that the PAM is not configured with the nullok option, which would allow accounts to log in automatically without a password.

Some Controls were marked Not Applicable due to particular elements like absence of GUI or features requiring Ubuntu Pro subscriptions. These exclusions were documented as well to provide clarity in my methodology.

Overall, the instance achieved compliance for only the applied CAT I controls. This project presents understanding of addressing critical security measures and an understanding of cloud principle. 
The methodology is practical for a learning environment and provides a secure, documented lab instance.

## Total findings
- Total Rule Evaluated: 14
- Compliant: 11
- Non-compliant: 0
- Not Applicable: 3
