## Reverse Engineering of an Old Encryption Program

One fine day another member of a cryptography chat asked about an old MS-DOS program.
It was attached to an old infosec e-book in the form of UU-encoded text and described as

> a simple, but extremely reliable program which uses original algorithms of multi-step polymorphic encryption with the use of two keys

It became an interesting challenge to reverse-engineer the program and see what it does.
This repository will contain the original program as well as my findings about it.

A stretch goal is to re-implement the program in Python.


### General Overview

The program is a simple MS-DOS COM-file. When it's run without any arguments it prints the following message:

```
Non-Decoding E-mail Cryptor(tm) version 1.0 Beta - 4
(C) 1997-2000 Microsoft Corparation, All Rights Reserved
This version for internal use only - not for distribution
Registred to [Philip Zimmermann]

For details on licensing and distribution, see the www.shownomercy.com
For contact with the author, write to root@pentagon.gov

Usage:
To encrypt a text file,  type : ndec e TextFile OutFile [pass1] [pass2]
To decrypt a crypt file, type : ndec d CryptFile OutFile [pass1] [pass2]
```

Few initial observations:

 * The output is always 1 byte longer than the input
 * The output is randomized, i.e. for the same input the output will be totally different
 * By running it few times with the same input, the output will repeat quite soon

The assumption (later proven right) was that there's 1 byte random seed that is used in the encryption process.


### Unpacking

It is clear that the program is written in assembly, and the code is packed either to reduce the file size or to complicate reverse engineering.
For analysis I used Borland Turbo Debugger installed on Free DOS running in QEMU.

The program starts as follows:

```
00000000  50                push ax
00000001  B8751F            mov ax,0x1f75    ; how much space is needed
00000004  BA2E05            mov dx,0x52e     ; (this is where we're going to copy the code)
00000007  3BC4              cmp ax,sp        ; check if there's enough space
00000009  7379              jnc 0x84         ; exit if not
0000000B  8BC4              mov ax,sp        ; copying the code below stack
0000000D  2D4203            sub ax,0x342     ;
00000010  25F0FF            and ax,0xfff0    ; align to the paragraph boundary
00000013  8BF8              mov di,ax        ; destination
00000015  B9A100            mov cx,0xa1      ; copying 0xa1 words
00000018  BE8E01            mov si,0x18e     ; source
0000001B  FC                cld
0000001C  F3A5              rep movsw        ; copy
0000001E  8BD8              mov bx,ax        ; the destination address is aligned,
00000020  B104              mov cl,0x4       ; address it as a segment
00000022  D3EB              shr bx,cl
00000024  8CD9              mov cx,ds
00000026  03D9              add bx,cx        ; bx is now the segment of the copied code
00000028  53                push bx
00000029  33DB              xor bx,bx        ; offset is 0
0000002B  53                push bx
0000002C  CB                retf             ; jump to the copied code
```
