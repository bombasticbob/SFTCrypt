# SFTCrypt

  This is a simple encryption program that uses a unique encryption algorithm
that was invented by me back in 1998 (or perhaps earlier).   I described it
in prose on http://mrp3.com/encrypt.html back when it was illegal to export
encryption from the USA over a certain number of (pathetic) bits, 56 if I
remember correctly.  But describing in PROSE was LEGAL.  So I did.

  Later the laws were sensibly changed.  In short the method must be
disclosed.  Making the source public discloses it to the world.  But I had
already sent a copy to some gummint agency decades ago, as was required.
So there you go.  All nice and legal.

  The key length is fixed at 128 bits.  The algorithm itself really can't do
any better.  And it is not perfect by any means.  But it DOES work, and it's
not very complicated.  The pseudo-random sequences that are generated as
part of the algorithm use a method similar to a CRC, which is "not bad" at
the very least.  These pseudo-random numbers then build the translation
tables for the actual encryption.  So simple!


## GUTLESS DISCLAIMER

  Just to point out, there are WAY better methods of encryption out there,
methods like AES for example, that have source files available and are part
of standard packages (like openssl or gpg).  So there is nothing really
'secret' or 'special' about this one, except that it's different.  Because
it is simple, you could theoretically adjust it in any way you see fit to
make improvements, or maybe even make it ineffective, or add back doors,
or whatever else you might want to do.  For this reason there can be

  NO WARRANTIES NOR CLAIMS OF LIABILITY WHATSOEVER

with respect to this software, which is being provided 'as-is' in an
imperfect state.


## Use on Windows

  For now, you must build it with CYGWIN if you need the full command line
features, in particular prompting for the password.  The program still may
compile and run under Win32 but I have not tested it with 64-bit builds,
and the password prompt is not complete [there are gaps in the code].


## Storing Github Generated keys

  Github has recently changed its policy with respect to logins using the
'git' utility.  In short, logging in with a password won't be supported at
some point in the future.  Instead, you need to generate a token.  The tokens
can be assigned specific permissions, though, which is somewhat nice, but you
lose the convenience of a 'rememberable' pass phrase.  If you store your
credentials this isn't a big deal.  But if you are like me and often use git
to obtain source on 'some random device' or on a machine owned by others
[such as a client], you still need a way of getting to your credentials
without having to insecurely put them onto a piece of paper or a USB drive
or (even worse) a plain text file.

  This program CAN provide you with a solution!

  First, store your credentials in a way similar to this:

    sftcrypt -P > ~/my.github.key

  When prompted, enter your private pass phrase to encrypt with. Then, enter
the text for the key.  Hit 'enter' and then press the CTRL+D key to mark 'eof'
on input.  

  (if this were run in a windows environment you would use CTRL+Z instead).

  This stores your key, encrypted, as ~/my.github.key .

  Now I use the X11 desktop and so I will typically want the key in the X11
clipboard.  To do this you'll need the 'xclip' utility, which is a standard
X11 util available on just about any POSIX system (Linux, FreeBSD, etc.).
Then, create a shell script similar to this:

    #!/bin/sh

    sftcrypt -d -P < ~/my.github.key | xclip -selection clipboard

  When you run the script, you will be prompted for the pass phrase that you
entered when you encrypted it.  Enter the same pass phrase correctly, and
your github key will be placed on the X11 clipboard.  Then, from an X
terminal, use whatever method you typically use to insert the clipboard text
when you're prompted for the password by 'git'.

  Since you PROBABLY would have clipped it out of a text file and then pasted
from the clipboard anyway, this provides you with a nice and secure way that
you could put it into the clipboard from a file you could put just about
anywhere without possibly compromising your github key.

  note:  if you type the pass phrase wrong, you'll see binary garbage instead
         of text. you could write an addition to the shell script to check
         the SHA hash before you paste it, which would also be secure, to
         detect a bad password.  I leave that exercise up to you.



## BUILDING

Use 'make' to invoke 'Makefile' or compile as follows:

  c++ -o sftcrypt sftcrypt.cpp


## LICENSE

  You may, at your discretion, use and distribute this software
  under a Creative Commons license (see LICENSE).

  This software has been released into the public domain.


## USAGE

  When you execute sftcrypt with the '-h' switch, you'll see the following:

    SFTCRYPT - Encryption/Decryption technology (c) 1998 by SFT Inc.

    COMMAND LINE:  SFTCRYPT [-h] [-d] [[-p] key|-P[-]] [input file [output file]]
        where      'key' is a 128-bit key defined by a binary hex literal
                   or a quoted 'key phrase' [if '-p' specified]
         and       -P prompts for a pass phrase (via console)
                   specifying '-P-' will echo the passphrase; use with discretion
         and       'input file' is an optional input file (default is STDIN)
         and       'output file' is the default output file (default is STDOUT)
         and       '-d' indicates "decrypt"
         and       '-h' prints this message


  Typically you'll use the '-P' parameter to prompt for a pass phrase.  You
can also use '-p "pass phrase"' to specify the pass phrase on the command
line.

  Following any possible pass phrase (and other parameters), the next
parameter is the input file name, followed by the (optional) output file name.
So, in short, if you specify no file names, sftcrypt reads from stdin and
writes to stdout.  If you only specify an input file, it will write to stdout.
Otherwise it reads and writes to the specified files.

  The '-d' parameter can be used to encrypt as well as decrypt.  However,
the algorithm will work 'backwards' so that you need to leave it off to
decrypt.

  Additionally, if you have a 128 bit key (32 hexadecimal digits) that you
want to encrypt with, you can specify ths on the command line via '-k'.



