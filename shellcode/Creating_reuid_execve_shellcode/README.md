# Creating a reuid(0,0) execve("/bin/sh") shellcode
I was sitting on the other day, struggling with getting a root shell on a challenge. The concept of the challenge was simple. You got SSH credentials and there was a binary file owned by root, with the SUID bit set.
If you just do an execve("/bin/sh") on this binary, your shell will just drop privileges and you will end up with a normal user shell.
Calling setuid(0) did absolutely nothing for me and I still ended up with a normal user shell.
Although this challenge wasn't quite intended to be solved by getting a root shell. I was determined to do so and found out that you can call execve on /bin/sh with the -p parameter. And I created an exploit that did exactly this.
After discussing my overly complicated exploit with a friend, it turned out that I had gotten the idea completely wrong.
To keep privileges in the shell you just need to make sure that the uid is set to 0 and the euid is set to 0.
I looked around on http://shell-storm.org/shellcode/ and realized that although there are shellcodes which call /bin/sh with setuid(0). There are none which call /bin/sh with both setuid(0) and seteuid(0).
They do however exist for ash, bash etc. So I decided to write my own.
