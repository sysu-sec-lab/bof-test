### Makefile --- 

## Author: sysu-sec-lab@googlegroups.com
## Version: $Id: Makefile,v 0.0 2013/03/26 13:20:40 Exp $
## Keywords: buffer overflow

CC=gcc
CFLAGS=-g

default:
	$(CC) $(CFLAGS) -fstack-protector-all -o main_linux main_linux.c
	$(CC) $(CFLAGS) -o main_linux2 main_linux2.c
	$(CC) $(CFLAGS) -o getenvaddr getenvaddr.c

clean:
	rm -rf *.o *~ main_linux main_linux2 getenvaddr exploit*

### Makefile ends here
