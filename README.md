# Tajimari

the Open Source and Pure C++ Packer for eXecutables

> `Tajimari` is currently a normal packer for **PE eXecutables**, it will soon become a `VIRTUAL` based packer.

## Overview

`Tajimari` contains two project: 
 - The main program: `Tajimari Main`
 - The shellcode generator: `ShellcodeTemplate`

### Tajimari Main

The main program, contains `PeMaster`, which is the core of `Tajimari`, providing function like: PE parse, rebuild and etc.

Pack a program and inject `ShellcodeTemplate` into it.

### ShellcodeTemplate

The shellcode generator using `MSVC`

Used as an alternative entry point for original program. There you can add some tweaks for the program itself or do some decryption for packer

Depends on `lazy-importer` to use `Windows API`

## Build

1. Setup `Visual Studio`
2. Install and integrate `vcpkg`
4. Tweak paths in `Tajimari Main`'s main.cpp
5. Open the `.sln` file and enjoy it

## Donate 

![](https://github.com/WINKILLERS/WINKILLERS.github.io/blob/master/images/alipay.jpg)
![](https://github.com/WINKILLERS/WINKILLERS.github.io/blob/master/images/wechat.png)

## Contact

Telegram Group: https://t.me/miyamimitsuha
