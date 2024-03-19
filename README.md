## Reverse Engineering of an Old Encryption Program

One fine day another member of a cryptography chat asked about an old MS-DOS program.
It was attached to an old infosec e-book in the form of UU-encoded text and described as

> a simple, but extremely reliable program which uses original algorithms of multi-step polymorphic encryption with the use of two keys

It became an interesting challenge to reverse-engineer the program and see what it does.
This repository will contain the original program as well as my findings about it.

A stretch goal is to re-implement the program in a high-level language.


### Go Implementation

I was able to re-implement the encryption part in Go, it can be built using `make` and run as:

```sh
./ndec -i <input-file> -o <output-file> -p1 <password1> -p2 <password2> [-iv <iv>] <command>
```

where `command` is either `encrypt` or `decrypt` and `iv` is an optional initialization vector (1 byte in the hexadecimal form).

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

In short, it copies a piece of code slightly below the top of the stack and jumps to it. The copied code in turn copies a bunch of data
right below itelf, and does a lot of magic with it that I am yet to process. Then it again jumps to the start of it.

My immediate goal was to figure out the encryption part, so for now I'll skip the obfuscation.
If you ever want to follow my steps, just scroll down until the next `retf` instruction and start from there.


### Encryption

The encryption consists of the few steps:

 * Generate a pseudorandom gamma from the first password
 * Generate a 1 byte initialization vector (IV), it's stored at `DS:910` and written to the output file
 * Generate a 1-byte hash from the second password
 * Walk through the input byte by byte and combine it with the gamma using one of the three cyclically changing operations: `xor`, `sub` and `add`
   (the operation is changed by rewriting the assembly instruction right in the code)
 * Walk through the input again and encrypt it byte by byte using the IV, the hash and the gamma (the exact algorithm is TBD)


#### Gamma Generation

This is the assembly code that generates gamma from the first password. There seems to be a bug here,
since if we look at [Round 2](#round-2-mix-with-the-gamma-the-second-password-hash-and-the-iv),
we see that it assumes that the gamma is zero-terminated, and here it seems to try avoid having zeros in the middle,
but it doesn't work.

```assembly
        ; Input: DS:DI = pointer to the password (in fact, DI=0x508)
        ; will be modified in place

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
        neg   al        ; I don't know what it's supposed to do, al is always 0 here anyway
        ror   al, cl    ; it probably was intended to make gamma zero-terminated (see round 2), but it doesn't work
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

#### Round 1: Mix the plaintext with the gamma

To be quite precise, the gamma here is not what's usually called a gamma. Either due to a coding mistake or a misunderstanding,
instead of applying each byte of the gamma to the matching byte of the input, the entire gamma is applied to each character,
thus being reduced to a single byte. The only thing that changes is the operation that's used; it's cyclically varies
between `XOR`, `SUB` and `ADD`. The assembly code is as follows:

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
        pop   cx

        ; ... the rest of the encryption procedure
```

The matching Go code (instead of looping through the "gamma" each time, I first reduce it to a single byte):

```go
func Round1(data, gamma []byte) {
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

#### Round 2: Mix with the gamma, the second password hash and the IV

On this round, the gamma is applied to the plaintext again, this time byte by byte,
but the assumption seems to be that it's zero-terminated, which is not the case (likely due to a bug in the gamma generation code).
As a result, the gamma may be not fully used.
This round also makes use of the IV and the second password hash. The assembly code is as follows:

```assembly
        ; Input: CX = data length

        push  cx
        mov   di, 0x1075        ; destination address
        xor   bx, bx
        mov   ah, cs:[0x910]    ; IV
read_gamma:
        mov   al, cs:[bx+0x508] ; gamma character
        or    al, al
        jne   not_zero
        xor   bx, bx            ; it assumes that the gamma is zero-terminated?
        jmp   read_gamma        ; (because it's not)
not_zero:
        add   al, cs:[0x909]    ; password hash
        xor   cs:[di], ah
        add   cs:[di], al
        xor   cs:[di], al
        sub   cs:[di], al
        ror   cs:byte ptr [di], cl
        ror   ah, cl
        xor   al, ah            ; this doesn't seem to do anything
        inc   di
        inc   bx
        loop  read_gamma
        pop   cx
```

The matching Go code:

```go
func Round2(data, gamma []byte, iv, pwHash byte) {
	ctr := len(data)
	gi := 0
	for i, b := range data {
		x := gamma[gi]
		if x == 0 {
			x, gi = gamma[0], 0
		}
                gi++

		x += pwHash
		b = ((b ^ iv) + x) ^ x - x
		b = ror8(b, ctr)
		iv = ror8(iv, ctr)
		data[i] = b
		ctr--
	}
}
```

#### Round 3: Mix with the second password and the gamma hash

The last round is similar to the second, except that it uses the plain second password and the gamma hash:

```assembly
        push  cx
        mov   di, 0x1075          ; destination address
        mov   ah, cs:[0x908]      ; gamma hash
        xor   bx, bx

next_byte:
        mov   al, cs:[bx+0x608]   ; next password character
        sub   cs:[di], al
        xor   cs:[di], al
        add   cs:[di], al
        neg   cs:byte ptr [di]
        sub   cs:[di], ah
        ror   ah, cl
        neg   ah
        xor   ah, al
        inc   di
        inc   bx
        or    al, al
        jne   not_zero
        xor   bx, bx              ; to the password start
                                  ; (but we have still used the terminating zero already)
not_zero:
        loop  next_byte
        pop   cx
        ret                       ; the encryption is done
```

The matching Go code:

```go
func Round3(data, password []byte, gammaHash byte) {
	ctr := len(data)
	password = append(password, 0)
	for i, b := range data {
		x := password[i%len(password)]
		b = -((b - x) ^ x) - x - gammaHash
		data[i] = b
		gammaHash = (-ror8(gammaHash, ctr)) ^ x
		ctr--
	}
}
```

### Decryption

Decryption part is the inverse of encryption, here's the code for it in the reverse order
(gamma and hash generation is omitted, it's the same code):


#### Round 3 Inverse:

```assembly
        push  cx
        mov   di, 0xc75          ; encrypted data
        mov   ah, cs:[0x908]     ; gamma hash
        xor   bx, bx
next_byte:
        mov   al, cs:[bx+0x608]  ; next password character
        add   cs:[di], ah
        neg   cs:byte ptr [di]
        sub   cs:[di], al
        xor   cs:[di], al
        add   cs:[di], al
        ror   ah, cl
        neg   ah
        xor   ah, al
        inc   di
        inc   bx
        or    al, al
        jne   not_zero
        xor   bx, bx
not_zero:
        loop  next_byte
        pop cx
```

#### Round 2 Inverse:

```assembly
        push  cx
        mov   di, 0xc75         ; encrypted data
        xor   bx, bx
        mov   ah, cs:[0x910]    ; IV

read_gamma:
        mov   al, cs:[bx+0x508] ; gamma character
        or    al, al
        jne   not_zero
        xor   bx, bx
        jmp   read_gamma

not_zero:
        add   al, cs:[0x909]    ; password hash
        rol   cs:byte ptr [di], cl
        add   cs:[di], al
        xor   cs:[di], al
        sub   cs:[di], al
        xor   cs:[di], ah
        ror   ah, cl
        xor   al, ah
        inc   di
        inc bx
        loop read_gamma
        pop cx
```

#### Round 1 Inverse:

Round 1 decryption is exactly like encryption just the operations change in another order: `XOR`, `ADD`, `SUB`.