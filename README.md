## Reverse Engineering of an Old Encryption Program

One fine day another member of a cryptography chat asked about an old MS-DOS program.
It was attached to an old infosec e-book in the form of UU-encoded text and described as

> a simple, but extremely reliable program which uses original algorithms of multi-step polymorphic encryption with the use of two keys

It became an interesting challenge to reverse-engineer the program and see what it does.
This repository will contain the original program as well as my findings about it.

A stretch goal is to re-implement the program in C.


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

<details><summary>Click to expand</summary>

```assembly
        push ax
        mov ax,0x1f75    ; how much space is needed
        mov dx,0x52e     ; (this is where we're going to copy the code)
        cmp ax,sp        ; check if there's enough space
        jnc 0x84         ; exit if not
        mov ax,sp        ; copying the code below stack
        sub ax,0x342     ;
        and ax,0xfff0    ; align to the paragraph boundary
        mov di,ax        ; destination
        mov cx,0xa1      ; copying 0xa1 words
        mov si,0x18e     ; source
        cld
        rep movsw        ; copy
        mov bx,ax        ; the destination address is aligned,
        mov cl,0x4       ; address it as a segment
        shr bx,cl
        mov cx,ds
        add bx,cx        ; bx is now the segment of the copied code
        push bx
        xor bx,bx        ; offset is 0
        push bx
        retf             ; jump to the copied code
```
</details>

In short, it copies a piece of code slightly below the top of the stack and jumps to it. The copied code in turn copies a bunch of data
right below itelf, and does a lot of magic with it that I am yet to process. Then it again jumps to the start of it.

My immediate goal was to figure out the encryption part, so for now I'll skip the obfuscation.
If you ever want to follow my steps, just scroll down until the next `retf` instruction and start from there.


### Initialization

Then the boring part follows, command line arguments are parsed, input and output files are opened and their handles are stored to
`DS:0504` and `DS:0506` respectively. A random 8-bit number is generated by reading from the ports `0x40` and `0x41`.
The number (hereafter called IV, the Initialization Vector) is both stored at the address `DS:910` and written to the output file.


### Encryption

The encryption consists of the few steps:

 * Generate a random gamma from the first password (the exact algorithm is TBD)
 * Walk through the input byte by byte and combine it with the gamma using one of the three cyclically changing operations: `xor`, `sub` and `add`
   (the operation is changed by rewriting the assembly instruction right in the code)
 * Generate a 1-byte hash from the second password
 * Walk through the input again and encrypt it byte by byte using the IV, the hash and the gamma (the exact algorithm is TBD)


#### Gamma Generation

This is the assembly code that generates gamma from the first password:

<details><summary>Click to expand</summary>

```assembly
        ; Input: DS:DI = pointer to the password (in fact, DI=0x508)

        not   word ptr [di]
        mov   si, di
        lodsw
        mov   dx, ax
        mov   cx, 007d

cycle:
        lodsw
        sub   al, ah
        not   al
        dec   dl
        xor   al, dl

        or    al, al
        jne   skip
        neg   al        ; I don't know what it's supposed to do
        ror   al, cl    ; (al is always 0 here anyway)
skip:
        stosbb
        ror   dl, cl
        xor   dl, dh
        shl   dh, 1
        add   dh, al
        sub   dl, dh
        neg   dh
        loop  cycle

        ret
```
</details>

The matching C code:

```c
inline static uint8_t ror(uint8_t x, uint8_t n) {
    if (!(n = n & 7)) {
        return x;
    }

    return (x >> n) | (x << (8 - n));
}

// data is expected to contain the password padded with zeros and be at least len+2 bytes long.
// In the real program len is always 0x7d
void generate_gamma(uint8_t *data, size_t len) {
    uint8_t st1 = ~data[0];
    uint8_t st2 = ~data[1];
    size_t i = 0, j = 2;

    for (size_t k = len; k; k--, j+=2) {
        uint8_t cur = ~(data[j] - data[j+1]) ^ (--st1);
        data[i++] = cur;

        st1 = ror(st1, k) ^ st2;
        st2 = -(st2 << 1) - cur;
        st1 += st2;
    }
}
```
