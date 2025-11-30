# Methodology

## Notes
-Only CAT I benchmarks will be applied since these are of the highest severity
-The system contains a single root account.
-Ubuntu Pro benchmarks were excluded due to budget limitations

## Environment Setup
1. Created an AWS account and launched an EC2 instance
2. Selected Ubuntu for Application and OS Images
3. Created an EC2 keypair for access via SSH
4. Go to the loaction of the EC2 key:
```
cd C:\Users\Suwar\Desktop\Websites
```
5. Connected to the EC2 instance via SSH:
```
ssh -i "ec2-keypair.pem" ubuntu@ec2-56-228-25-208.eu-north-1.compute.amazonaws.com
```
6. Update the system:
```
sudo apt update

sudo apt upgrade
```

## Benchmark Application
**Aautomated Rules**
1. Verification: For each control the system got checked according to the CIS benchmark application.
2. Remediation: If the rule was not compliant, changes were implemented according to the CIS benchmark.
3. Validation: Checking the implementaion of the rule to confirm that the rule was properly applied.

## Automated Rules
**1.4 UBTU-24-100030**  
**Group ID:** V-270647  
**Rule ID:** SV-270647r1066430

-**Reason:** Telnet provides an unencrypted remote access service
-**Verify:** dpkg -l | grep telnetd
-**Output:** nothing
-**Conclusion:** Telnet package was not installed. This rule is Compliant

