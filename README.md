## Reverse-Engineering of an Old Encryption Program

One fine day another member of a cryptography chat asked about an old MS-DOS program.
It was attached to an old infosec e-book in the form of UU-encoded text and described as

> a simple, but extremely reliable program which uses original algorithms of multi-step polymorphic encryption with the use of two keys

It became an interesting challenge to reverse-engineer the program and see what it does.
This repository will contain the original program as well as my findings about it.

A stretch-goal is to reimplement the program in Python.


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
