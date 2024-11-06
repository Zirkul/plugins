# Zirkul CLI Plugins repository
Zirkul CLI is a portable tool for automating cyber security tasks for Pros and newbies trough plugins created and mantained by the community, all plugins in this repository are open source and everybody is welcome to join and provide scripts and plugins for the community.

This tool is free and it's provided as portable executable files that have been tested in Windows x64, OSX Apple Silicon and Linux distros such as Kali or ParrotOS.

## Use cases
* Automate DAST, SAST, SCA or any other vulnerability scan.
* Use crypto functions easily for generating hashes, encoding, decoding and more from any OS.
* Run almost any tool available as command and do something with the output or parse the results.
* Integrate any python exploit into an automated process.
* Interact with Web APIs and external tools.

The command line interface (CLI) is similar to metasploit framework and can be used for running functions, plugins and export results as json or CSV, all instructions can be stored in a script that can be used for automating the whole process simplifying the repetitive work developers and security folks usually have.

## Download

Windows:
```
curl -o zirkul.exe https://app.zirkul.com/api/agent/windows

```
Linux:
```
curl -o zirkul https://app.zirkul.com/api/agent/linux
```
OSX (Apple Silicon):
```
curl -o zirkul.pkg https://app.zirkul.com/api/agent/osx
```
## Running
From the terminal in your computer simply run the tool:
Windows:
```
zirkul.exe
```
Linux:
```
chmod +x zirkul
zirkul
```
OSX (Apple Silicon):
```
sudo installer -pkg zirkul.pkg -target ~/Applications
zirkul
```
Optionally in OSX you can install the tool by simply opening the zirkul.pkg file directly from finder.
![image](https://github.com/user-attachments/assets/c393bedf-c269-4367-a566-72f5aa32db1a)

# Getting started
There are many things you can do with Zirkul CLI, let's start by running the tool with the argument `--help` for listing the options available:

![image](https://github.com/user-attachments/assets/7c496acf-cc01-4121-a114-3b1687e32e65)

You can ignore the commercial features not discussed here, for now we can focus in the argument `--script` for running a script but first let's create a new text file in the editor of your preference:

![image](https://github.com/user-attachments/assets/2591d246-dac8-4189-9a94-0a2dd2524dc0)

Then you can run your script with:
``` bash
zirkul --script my_script.txt
```

![image](https://github.com/user-attachments/assets/fe4d7de4-5d56-4000-a0ed-6ee755163b3c)

For more information see the [docs](https://docs.zirkul.com/zirkul-agent/running-the-agent/command-line-interface)
