### N-day Exploits

- [CVE-2019-18634](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2019-18634): Linux sudo LPE exploit for a stack-based buffer overflow in `tgetpass.c`
- [CVE-2020-28018](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2020-28018): Linux Exim RCE exploit for a Use-After-Free in `tls-openssl.c`
- [CVE-2020-9273](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2020-9273): Linux ProFTPd RCE exploit for a Use-After-Free in pool allocator
- [CVE-2021-3156](https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156): Linux LPE exploit for a heap-based buffer overflow in sudo
- [CVE-2021-40444](https://github.com/lockedbyte/CVE-2021-40444): Microsoft Windows RCE exploit for a MS Office bug chain
- [CVE-2022-0185](https://www.openwall.com/lists/oss-security/2022/01/25/14): Linux Kernel LPE exploit for an integer underflow in `fs_context.c`
- [CVE-2022-2586](https://www.openwall.com/lists/oss-security/2022/08/29/5): Linux Kernel LPE exploit for an nft_object Use-After-Free

### Talk slides

- [Exploiting sudo CVE-2021-3156: From heap-based overflow to LPE/EoP](https://github.com/lockedbyte/slides/blob/main/Exploiting%20sudo%20CVE-2021-3156_%20%20From%20heap-based%20overflow%20to%20LPE_EoP.pdf): Talk about the process and internals of the sudo heap-based overflow vulnerability and its exploitation paths.
- [CVE-2020-28018: From Use-After-Free to Remote Code Execution](https://github.com/lockedbyte/slides/blob/main/CVE-2020-28018:%20From%20Use-After-Free%20to%20RCE.pdf): Talk on going through the internals and exploitation of a Use-After-Free vulnerability in Exim to achieve Remote Code Execution.
- [Confronting CFI: Control-flow Hijacking in the Intel CET era for memory corruption exploit development](https://github.com/lockedbyte/slides/blob/main/Confronting%20CFI_%20Control-flow%20Hijacking%20in%20the%20Intel%20CET%20era%20for%20memory%20corruption%20exploit%20development.pdf): Talk on analyzing modern CFI mitigations and their impact on memory corruption exploits.

### Blog posts

- [Having fun with a Use-After-Free in ProFTPd (CVE-2020-9273)](https://adepts.of0x.cc/proftpd-cve-2020-9273-exploit/): Blog post on exploiting a Use-After-Free in ProFTPd to achieve Remote Code Execution
- [From theory to practice: analysis and PoC development for CVE-2020-28018 (Use-After-Free in Exim)](https://adepts.of0x.cc/exim-cve-2020-28018/): Blog post analyzing a Use-After-Free vulnerability in Exim and the development of a RCE exploit
- [CVE-2021-3156 – sudo heap-based overflow leading to privilege escalation (PoC development)](https://lockedbyte.com/blog/index.php/2021/02/19/cve-2021-3156-sudo-heap-based-overflow-leads-to-lpe/): Post about developing an exploit for a heap-based buffer overflow on sudo leading to LPE (CVE-2021-3156)
- [CVE-2019-18634 OOB write – analysis and development of a working PoC](https://lockedbyte.com/blog/index.php/2020/12/12/cve-2019-18634-oob-write-analysis-and-development-of-a-working-poc/): Post about the development of an exploit for a stack-based buffer overflow in sudo leading to LPE (CVE-2019-18634)

### Other projects

- [Protcheck](https://github.com/lockedbyte/protcheck): Parse ELF executables to identify enabled memory mitigations
