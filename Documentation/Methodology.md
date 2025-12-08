# Methodology

## Notes
- Only CAT I benchmarks will be applied since these are of the highest severity
- The system contains a single root account.
- Ubuntu Pro benchmarks were excluded due to budget limitations

## Environment Setup
1. Created an AWS account and launch an EC2 instance
2. Select [Ubuntu](Screenshots/Choosing_ubuntu.png) for Application and OS Images
3. Create a [EC2](Screenshots/Create_ec2-keypair_key.png) keypair for access via SSH
4. Go to the saved location of the EC2 key:
```bash
cd C:\Users\Suwar\Desktop\Websites
```
5. Connected to the EC2 instance via [SSH](Screenshots/ssh_into_ec2:
```bash
ssh -i "ec2-keypair.pem" ubuntu@ec2-56-228-25-208.eu-north-1.compute.amazonaws.com
```
6. Update the system:
```
sudo apt update

sudo apt upgrade
```

## Benchmark Application
**Automated Rules**
1. Verification: For each control the system got checked according to the CIS benchmark application.
2. Remediation: If the rule was not compliant, changes were implemented according to the CIS benchmark.
3. Validation: Checking the implementation of the rule to confirm that the rule was properly applied.

## Automated Rules

### 1.4 UBTU-24-100030 
**GROUP ID:** V-270647

**RULE ID:** SV-270647r1066430

- Rationale: Telnet provides an unencrypted remote access service
- Validate:
```bash
dpkg -l | grep telnetd
```
- Output: nothing
- Double-Check:
```
sudo apt-get remove telnetd
```
- Output:
```
Package 'telnetd' is not installed, so not removed
```
- **Result:** Telnet package was not installed. Compliant.
- [Screenshot](Screenshots/Telnet.png)

### 1.5 UBTU-24-100040
**GROUP ID:** V-270648

**RULE ID:** SV-270648r1066433

- Rationale: Provides unencrypted remote access service that could expose credentials.
- Validate: 
```bash
dpkg -l | grep rsh-server
```
- Output: nothing
- **Result:** RSH service package was not installed
- [Screenshot](Screenshots/RSH_service.png)


### 1.22 UBTU-24-100800
**GROUP ID:** V-270665

**RULE ID:** SV-270665r1067133

- Rationale: Confidentiality and Integrity can both be compromised if information is intercepted and either read or altered via SSH.
- Validate:
```bash
sudo dpkg -l | grep openssh
```
- Output:
```
ii  openssh-client                     1:9.6p1-3ubuntu13.14                    amd64        secure shell (SSH) client, for secure access to remote machines
ii  openssh-server                     1:9.6p1-3ubuntu13.14                    amd64        secure shell (SSH) server, for secure access from remote machines
ii  openssh-sftp-server                1:9.6p1-3ubuntu13.14                    amd64        secure shell (SSH) sftp server module, for SFTP access from remote machines
```
- **Result:** Open ssh is installed. Compliant.
- [Screenshot](Screenshots/ssh_package_check.png)


### 1.23 UBTU-24-100810
**GROUP ID:** V-270666

**RULE ID:** SV-270666r1066487

- Rationale: SSH must be enabled and active to ensure secure remote access to protect confidentiality and integrity.
- Validate:
```
sudo systemctl is-enabled ssh
```
- Output:
```
disabled
```
- Remediation:
```bash
sudo systemctl enable ssh.service --now
```
- Output:
```
Synchronizing state of ssh.service with SysV service script with /usr/lib/systemd/systemd-sysv-install.
Executing: /usr/lib/systemd/systemd-sysv-install enable ssh
Created symlink /etc/systemd/system/sshd.service → /usr/lib/systemd/system/ssh.service.
Created symlink /etc/systemd/system/multi-user.target.wants/ssh.service → /usr/lib/systemd/system/ssh.service.
```
- Double-check:
```bash
sudo systemctl is-enabled ssh
```
- Output:
```
enabled
```
- **Result:** SSH is enabled. Compliant.
- [Screenshot](Screenshots/Systemctl_is_active.png)


### 1.32 UBTU-24-102000
**GROUP ID:** V-270675

**RULE ID:** SV-270675r1066514

- Rationale: Successful authentication must not mean automatic access to sensitive resources based off of only certificates. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.
- Validate:
```bash
sudo grep -i password /boot/grub/grub.cfg
```
- Output: nothing
- Remediation: 
1. [Generate](Screenshots/Grub_password.png) an encrypted (grub) password for root by using the following command:
```
grub-mkpasswd-pbkdf2
```
2. Enter password twice
3. Copy the hashed password that you got
4. Modify
```
sudo sed -i '$i set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.6C2822CF2EA6F7AF9D365689A56F71E68866ED99E2BBDE183B3F28DF40FF70CA996175181B4CDAF08776F07811F028537DCC112C4CB44533391974F7FD8DEA86.FCB4AE31821F624CC5294CD3F3E9B8C670A9A247B30BBB76EF764A7DC7F6F96457AAB6C1D88A5AD83B55954B85D92703C8831C2F1523EAC914A3694804CDC621' /etc/grub.d/40_custom
```
5. Update the grub: 
```
sudo update-grub
```
- Output: 
```
Sourcing file `/etc/default/grub'
Sourcing file `/etc/default/grub.d/40-force-partuuid.cfg'
Sourcing file `/etc/default/grub.d/50-cloudimg-settings.cfg'
Generating grub configuration file ...
GRUB_FORCE_PARTUUID is set, will attempt initrdless boot
Found linux image: /boot/vmlinuz-6.14.0-1017-aws
Found initrd image: /boot/microcode.cpio /boot/initrd.img-6.14.0-1017-aws
Found linux image: /boot/vmlinuz-6.14.0-1015-aws
Found initrd image: /boot/microcode.cpio /boot/initrd.img-6.14.0-1015-aws
Warning: os-prober will not be executed to detect other bootable partitions.
Systems on them will not be added to the GRUB boot configuration.
Check GRUB_DISABLE_OS_PROBER documentation entry.
Adding boot menu entry for UEFI Firmware Settings ...
done
```
6. Double-Check it, it should start with password_pbkdf2 root and then your hash:
```bash
sudo grep -i password /boot/grub/grub.cfg
```
- Output: grub.pbkdf2.sha512.10000.6C2822CF2EA6F7AF9D365689A56F71E68866ED99E2BBDE183B3F28DF40FF70CA996175181B4CDAF08776F07811F028537DCC112C4CB44533391974F7FD8DEA86.FCB4AE31821F624CC5294CD3F3E9B8C670A9A247B30BBB76EF764A7DC7F6F96457AAB6C1D88A5AD83B55954B85D92703C8831C2F1523EAC914A3694804CDC621

- **Result:** Now we have verified that the operating system requires a password for authentication upon booting into single-user and maintenance modes. Compliant.
- [Screenshot](Screenshots/Modify_Grub.png)




### 1.65 UBTU-24-300022
**GROUP ID:** V-270708

**RULE ID:** SV-270708r1066613

- Rationale:  X11 display server can be exposed to attacks such as keystroke monitoring if X11 service is enabled. X11 forwarding should be enabled with caution since the X11 services are not required for the system's intended function.
- Validate:
```bash
sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"
```
- Output:
```
/etc/ssh/sshd_config:X11Forwarding yes
/etc/ssh/sshd_config:#  X11Forwarding no
```
- Remediation: 
```bash
sudo nano /etc/ssh/sshd_config
```
1. [Change](Screenshots/X11_fowarding_yes.png) the "X11Forwarding yes" to "X11Forwarding no" 
2. Save the file
3. For the effects to take place restart the SSH service:
```bash
sudo systemctl restart sshd.service
```
4. Double-Check:
```bash
sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"
```
- Output:
```
output:/etc/ssh/sshd_config:X11Forwarding no
/etc/ssh/sshd_config:#  X11Forwarding no
```
- **Result:**  We turned off X11 forwarding. Compliant.
- Screenshot [before](Screenshots/x11_forwarding_check.png)
- Screenshot [after](Screenshots/X11_fowarding_set_to_no.png)




### 1.68 UBTU-24-300025
**GROUP ID:** V-270711

**RULE ID:** SV-270711r1066622

- Rationale: A user who accidentally presses Ctrl-Alt-Delete can reboot the system if a graphical user interface is installed, which can lead the risk of short-term loss of availability of systems due to unintentional reboot.
- **Not applicable:** This rule is not applicable since there is no graphical environment installed on this system. Not applicable.





### 1.69 UBTU-24-300026
**GROUP ID:** V-270712

**RULE ID:** SV-270712r1068363

- Rationale: A user who accidentally presses Ctrl-Alt-Delete can reboot the system in the case of a mixed OS environment, which can lead the risk of short-term loss of availability of systems due to unintentional reboot.
- Validate:
```bash
systemctl status ctrl-alt-del.target
```
- Output:
```
○ reboot.target - System Reboot
     Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled; preset: enabled)
     Active: inactive (dead)
       Docs: man:systemd.special(7)
```
- Remediation:
```bash
sudo systemctl mask ctrl-alt-del.target
```
- Output:
```
Created symlink /etc/systemd/system/ctrl-alt-del.target → /dev/null.
```
- Double-Check:
```bash
systemctl status ctrl-alt-del.target
```
- Output:
```
○ ctrl-alt-del.target
     Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
     Active: inactive (dead)
```
- **Result:** The Ctrl-Alt-Del sequence has been disabled to help prevent accidental system reboots. Compliant.
- [Screenshot](Screenshots/disabling_ctr_alt_del_p2.png)





### 1.70 UBTU-24-300027
**GROUP ID:** V-270713

**RULE ID:** SV-270713r1066628

- Rationale: If an account has no password, anyone could log in and run commands which poses a great security risk. Ensures that no user accounts on the system has  blank or empty passwords in /etc/shadow.
- Validate:
```
sudo awk -F: '!$2 {print $1}' /etc/shadow
```
- Output: nothing
- **Result:** All accounts on the system have a password, if that was not the case we would have either made a password for that account or locked it.
- [Screenshot](Screenshots/blank_pass.png)





### 1.71 UBTU-24-300028
**GROUP ID:** V-270714

**RULE ID:** SV-270714r1067119

- Rationale: All accounts on the system must have a password. Make sure that the PAM is not configured with the nullok option, which would allow accounts to log in even without a password even if the password exists in /etc/shadow.
- Validate:
```bash
grep nullok /etc/pam.d/common-auth /etc/pam.d/common-password
```
- Output:
```
/etc/pam.d/common-auth:auth     [success=1 default=ignore]      pam_unix.so nullok
```
- Remediation:
```
sudo nano /etc/pam.d/common-auth
```
- [Remove](Screenshots/nano_nullok) nullok
- **Result:** the PAM is not configured with the nullok option, so it is not possible anymore to log on to the account without authenticating. Compliant.
- [Screenshot](Screenshots/output_nullok)




### 1.74 UBTU-24-300031
**GROUP ID:** V-270717

**RULE ID:** SV-270717r1067177

- Rationale: Misconfigured SSH options allowing unattended or automatic login via SSH undermines system security.
- Validate:
```bash
egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config
```
- Output:
```
PermitEmptyPasswords no
PermitUserEnvironment no
```
- **Result:** Automatic login via SSH is disabled
- [Screenshot](Screenshots/auto_ssh)





### 1.101 UBTU-24-600030
**GROUP ID:** V-270744

**RULE ID:** SV-270744r1066721

- Rationale: Weak and untested encryption rule out the purposes of using encryption to protect data. FIPS-approved cryptographic modules protect classified information which adhere to the higher standards approved by the federal government.
- Validate: Not applicable
- **Result:** A subscription for the "Ubuntu Pro" plan is necessary to use the FIPS Kernel cryptographic modules and enable FIPS. Not applicable





## Manual Rules

### 1.93 UBTU-24-400370 
**GROUP ID:** V-270736

**RULE ID:** SV-270736r1066697

- Rationale: Mapping the user or group with a certificate is necessary to be able to determine the identity of the user or group for forensic analysis.
- Validate:
```bash
grep -i ldap_user_certificate /etc/sssd/sssd.conf
```
- Output:  
```
No such file or directory
```
- **Result:** This control applies only to systems using SSSD with LDAP or AD integration. The instance does not use SSSD, and the /etc/sssd/sssd.conf file is not present. Not applicable.





### 1.105 UBTU-24-600130
**GROUP ID:** V-270748

**RULE ID:** SV-270748r1066733

- Rationale: Only trusted users should have the ability to perform administrative tasks on the system. Giving people access to the sudo group that do not need it will increase the risk of mistakes or malicious actions that could harm the system.
- **Result:** Given there is only one user which is me, the control's requirements do not apply. The system's configuration already aligns with the security objective of preventing unnecessary or unauthorized local accounts. Compliant.
