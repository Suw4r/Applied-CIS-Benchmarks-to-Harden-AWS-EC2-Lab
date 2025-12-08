#Troubleshooting

## First Issue

**Attempted to set GRUB password to /etc/grub.d/40_custom using:**
```bash
sudo sed -i '$i set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.6C2822CF2EA6F7AF9D365689A56F71E68866ED99E2BBDE183B3F28DF40FF70CA996175181B4CDAF08776F07811F028537DCC112C4CB44533391974F7FD8DEA86.FCB4AE31821F624CC5294CD3F3E9B8C670A9A247B30BBB76EF764A7DC7F6F96457AAB6C1D88A5AD83B55954B85D92703C8831C2F1523EAC914A3694804CDC621'
```
**Which returned:**
```
sed: no input files
``` 
**Motive:** The command failed multiple times because I forgot to put /etc/grub.d/40_custom at the end of the text. Sed requieres a valid file at the end of the command which was not provided leading to the `sed: no input files` output
**Solution:** Put `/etc/grub.d/40_custom` at the end of the text.

## Second Issue

**Accessing sshd_config file:**
```
nano /etc/ssh/sshd_config
```
- Changed the "X11Forwarding yes" to "X11Forwarding no"
- Saved the file
- Output: `Permission denied`

**Motive:** Permission error happened due to forgetting to use sudo when editing a system file
**Solution:** Use `sudo nano /etc/ssh/sshd_config`
