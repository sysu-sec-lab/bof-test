bof_test.sh
===========

This script provides functions for testing OS security
flaws in buffer overflow field.
Main modern techniques against buffer overflow are as follow:
    1.Address space layout randomization (ASLR)
    2.Executable space protection (W^X)
    3.Stack smashing protection (SSP)
We will try to bypass these protections.

Some tips for you:
     1.Disable ASLR : echo 0 > /proc/sys/kernel/randomize_va_space
     2.Disable W^X : execstack -s BINARY_FILE( If you have execstack command)
     3.Disable SSP : gcc -fno-stack-protector XXX

Author
------
    Zhibin Zhang <zzbthechaos@gmail.com>

Dependencies
------------
    * ROPgadget
	  Enter ROPgadget and install by:
	  	`sudo make && sudo make install`
    * gdb

Usage
-----
    Execute Makefile:
    	 make
    Run in terminal:
    	`bash bof_test.sh`
    and choose whichever option you like.
    Be careful what your default shell is and not
    simply run with `./bof_test.sh`(for example, Ubuntu's
    default shell is dash).

    **If your system can't be bypass cause we got some bugs,
      please let us know and you can copy the file in example/
      to current directory and try again without `make`.**

Tested on(32-bits machine)
--------------------------
    * Gentoo-3.7.10
    * Ubuntu-12.04
    * Fedora
