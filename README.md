# ASREQRoast

Used to capture kerberos AS_REQ messages

## Usage

**Powershell**
```powershell
# Prompt for interface
.\ASREQRoast.ps1

# Specify interface and format
.\ASREQRoast.ps1.ps1 -Interface 1 -Format john

# No-file mode (print only)
.ASREQRoast.ps1 -Interface 1 -Format hashcat -NoFiles

# Verbose mode
.\ASREQRoast.ps1 -Interface 1 -Verbose
```

**Python**
```sh
# Prompt for interface
asreqroast.py

# Specify interface and format
asreqroast.py -i eth0 -f john

# Choose output directory
asreqroast.py -i eth0 -o ./captures

# No-file mode (print only)
asreqroast.py -nf
```
