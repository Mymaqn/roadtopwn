# Rop Emporium writeups

All challenges can be found for different architectures at https://ropemporium.com/

Time to listen to myself for once and Keep It Simple, Stupid.

I've completed ROP emporium during my free time ages ago, and have actually made my own buffer overflow challenges since, but it's about time that I actually started doing write-ups for what I know inside of binary exploitation, instead of just posting write-ups for the hard or complicated stuff. I feel like ROP Emporium encompasses the basics of my skillset quite well (although it's missing some cool stuff like sigret) so I think it's about time I did some write-ups for it.

If you don't know about ROP Emporium and you've somehow still stumbled upon my page by accident, then first of all. Hello. Second, ROP Emporium is a set of challenges that exist to teach an individual about Return-Oriented Programming, which usually can be exploited with the help of a buffer overflow.

The goal of the challenges is either:
1. Spawn a shell through the control flow of the program
2. Make the program print out the flag.txt file in the same directory

Once one of these 2 goals have been accomplished I will mark the challenge as completed. It should be noted that all binaries assume that you have ASLR enabled.

The goal of these write-ups is for them to be educational and teach ROP from the ground up. Although I do expect anyone reading this has a basic understanding of writing programs in C and some experience using Python.

## Setup
If you want to follow along this is the setup I'm using:

Konsole - Terminal Emulator (https://konsole.kde.org/)
Cutter - Disassembler (https://cutter.re/)
pwntools - binary exploitation framework for Python (https://github.com/Gallopsled/pwntools)
pwndbg/gdb - debugger (https://github.com/pwndbg/pwndbg)
ropper - ROP gadget finder (https://github.com/sashs/Ropper)

## Where to go?
Click on one of the challenge folders to read the write-up for a challenge. Otherwise use this TOC:


