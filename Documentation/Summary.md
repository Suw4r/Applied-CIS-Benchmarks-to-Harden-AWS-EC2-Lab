# Summary

This project demonstrated how to implement NIST/CIS Benchmarks to harden an AWS EC2 lab. The newest Ubuntu CIS benchmark steps were followed with focus being on on applying only the highest severity controls because 
those are the most critical, which then help reduces the security risks while following industry standard guidelines for system hardening.

The project started with setting up an AWS EC2 instance with Ubuntu server as the OS. SSH access was then used to connect to this instance. Every CAT I control was handled following this simple guide of verification, remediation and result.

Actions that were taken include:
- Enabled SSH
- Ensured SSH was configured correctly
- The requirements for the OS to have a password for authentication when booting into single-user and maintenance modes.
- The Ctrl-Alt-Del sequence was disabled which helps prevent accidental system reboots
- X11 display server was disabled since it can be exposed to attacks such as keystroke monitoring.
- Ensured that the PAM is not configured with the nullok option, which would allow accounts to log in automatically without a password.

Some Controls were marked Not Applicable due to certain elements like the lack of a GUI or features that require Ubuntu Pro subscriptions. These exclusions were documented as well to provide clarity in my methodology.

Overall, the instance met the requirements for compliance for the applied controls. This shows the importance of giving attention to critical security measures and an understand cloud ideas. 
The methodology used is practical for an environment to learn in and provides a secure, documented lab instance.

## Total findings
- Total Rule Evaluated: 14
- Compliant: 11
- Non-compliant: 0
- Not Applicable: 3
