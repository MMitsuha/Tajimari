# Tajimari

the Open Source and Pure C++ Packer for eXecutables

> `Tajimari` is currently a normal packer for **PE eXecutables**, it will soon become a `VIRTUAL` based packer.

## Overview

`Tajimari` contains two project: 
 - The main program: `Tajimari Main`
 - The shellcode generator: `ShellcodeTemplate`

### Tajimari Main

The main program

Pack a program and inject `ShellcodeTemplate` into it.

### ShellcodeTemplate

The shellcode generator using `MSVC`

Used as an alternative entry point for original program. There you can add some tweaks for the program itself or do some decryption for packer

Depends on `lazy-importer` to use `Windows API`

## Build

1. Setup `Visual Studio`
2. Install and integrate `vcpkg`
3. Build `3rd_party/LIEF`
3. Open the `.sln` file and enjoy it

## Donate 

![alipay](https://github.com/WINKILLERS/WINKILLERS.github.io/blob/master/images/alipay.jpg =100)
![wechat](https://github.com/WINKILLERS/WINKILLERS.github.io/blob/master/images/wechat.png =100)

## Contact

Telegram Group: https://t.me/miyamimitsuha
