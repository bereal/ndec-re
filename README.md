## Reverse Engineering of an Old Encryption Program

One fine day another member of a cryptography chat asked about an old MS-DOS program.
It was attached to an old infosec e-book in the form of UU-encoded text and described as

> a simple, but extremely reliable program which uses original algorithms of multi-step polymorphic encryption with the use of two keys

It became an interesting challenge to reverse-engineer the program and see what it does.
This repository will contain the original program as well as my findings about it.

A stretch goal is to re-implement the program in a high-level language.


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

 * Generate a pseudorandom gamma from the first password
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

The matching Go code:

```go
const gammaIters = 0x7d

func Gamma(password []byte) []byte {
	data := make([]byte, 0xff)
	copy(data, password)
	st1, st2 := 0xff^data[0], 0xff^data[1]
	i, j := 0, 2

	for k := -gammaIters; k < 0; k++ {
		st1--
		cur := 0xff ^ (data[j] - data[j+1]) ^ st1
		data[i] = cur
		i++
		j += 2

		st1 = bits.RotateLeft8(st1, k) ^ st2
		st2 = -(st2 << 1) - cur
		st1 += st2
	}

	return data
}
```

From the use of `data[j] - data[j+1]` it follows that only difference of the adjacent password characters matters for the result,
so e.g. `password` and `paxxxprd` produce the same gamma.

#### Hashing the gamma

The hash is generated from the gamma password and stored at `DS:908`, the assembly code:

```assembly
        ; Input: DS:DI = pointer to the gamma (DI=0x508)

        mov  cx, 0xff
        xor  ax, ax
cycle:
        sub  al, cs:[di]
        xor  ah, al
        add  al, ah
        neg  al
        inc  di
        loop cycle

        ret
```

The matching Go code:

```go
func GammaHash(data []byte) byte {
	var hash, state byte

	for _, b := range data {
		hash -= b
		state ^= hash
		hash = -hash - state
	}

	return hash
}
```


#### Hashing the second password

The second hash is generated in a similar way from the second password and storead at `DS:909`, the assembly code:

```assembly
        ; Input: DS:DI = pointer to the second password (DI=0x608)

        mov  cx, 0xff
        xor  ax, ax

cycle:
        add  al, cs:[di]
        sub  ah, al
        xor  al, ah
        not  ah
        inc  di
        loop cycle

        ret
```

The matching Go code:

```go
func PasswordHash(password []byte) byte {
	data := make([]byte, 0xff)
	copy(data, password)

	var hash, state byte

	for _, b := range data {
		hash += b
		state -= hash
		hash ^= state
		state ^= 0xff
	}

	return hash
}
```

#### Applying gamma to the plain text

To be quite precise, the gamma is not what's usually called a gamma. Either due to a coding mistake or a misunderstanding,
instead of applying each byte of the gamma to the matching byte of the input, the entire gamma is applied to each character,
thus being reduced to a single byte. The only thing that changes is the operation that's used; it's cyclically varies
between `XOR`, `SUB` and `ADD`. The assembly code is as follows:

<details><summary>Click to expand</summary>

```assembly
        ; Input: DS:SI = plaintext address (SI=0xC75)
        ;        DS:DI = destination address (DI=1075)
        ;        CS    = plaintext length

        ; Address 0x90A contains the operation table,
        ; i.e. bytes 2A, 02, 32 which correspond to SUB, ADD and XOR opcode prefixes

        xor   al, al     ; al refers to the current operation
        push  cx

plaintext_loop:
        push  ax
        lodsb
        push  cx
        mov   bx, 0x508  ; gamma address
        mov   cx, 0xff   ; gamma length

gamma_loop:
        mov   ah, cs:[bx]
operation:
        xor   al, ah     ; this is a self-modified instruction
        inc   bx
        loop  gamma_loop
        stosb

        pop   cx
        pop   ax
        push  ax
        mov   bx, 0x90A   ; operation table
        xlat
        mov   cs:[operation], al
        pop   ax
        inc   al
        cmp   al, 3
        jne   continue
        xor   al, al      ; reset to the first operation
continue:
        loop  plaintext_loop

        ; ... the rest of the encryption procedure
```
</details>

The matching Go code (instead of looping through the "gamma" each time, I first reduce it to a single byte):

```go
func ApplyGamma(data, gamma []byte) {
	var xor, sum byte
	for _, b := range gamma {
		xor ^= b
		sum += b
	}

	for i, b := range data {
		switch i % 3 {
		case 0:
			data[i] = b ^ xor
		case 1:
			data[i] = b - sum
		case 2:
			data[i] = b + sum
		}
	}
}
```