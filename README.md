# uHttpProxy
uHttpProxy是一个Embedded HTTP Proxy

主要特性
====
1. 支持HTTP HTTPS FTP<br>
2. 单进程，异步IO <br>
3. 性能优良，可同时支持30台机器大流量的代理访问（在2M/16M的osk-RTOS）<br>

代码移植
====
仅运行在RTK Soc的OSK系统上，
一致到Linux，可将代码中的MailMsg通信机制，换成epoll改装即可。
