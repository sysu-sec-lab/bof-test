/*
  -----------------------------------------------------
  getenvaddr.c                         
                                                          
  Created on: 2013/03/17 10:39:24                  
  Author: Zhibin Zhang
  Email: zzbthechaos@gmail.com               
                                                         
  -----------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[])
{
    char *ptr;
    if(argc < 3)
	{
	    printf("Usage:%s<environment var> <target program name>\n",argv[0]);
	    exit(0);
	}
    ptr = getenv(argv[1]);
    ptr += (strlen(argv[0]) - strlen(argv[2])) * 2;
    printf("%p\n", ptr);
    return 0;
}
