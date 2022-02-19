## Command Prompt in the context menu
This small tool allows the user to regain the option
to open the cmd shell from the directories and directories background.

Basically, after running the tool, you can Shift+Right Click any directory or directory background
and open a cmd shell from the same directory.

![example_pic](images/example.png)

## Build
open Developer PowerShell for VS {2019}
```
git clone https://github.com/AliRamberg/ShellExtensionsCMD
cd ShellExtensionsCMD/
cl.exe /Zi /EHsc /Fe: ShellExtensionsCMD.exe Advapi32.lib, *.cpp
```

### Note
The tool requires administrative previleges, as it is takes ownership of registry keys
