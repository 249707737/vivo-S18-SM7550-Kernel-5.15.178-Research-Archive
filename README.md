# vivo-S18-SM7550-Kernel-5.15.178-Research-Archive
vivo S18 (PD2323 / SM7550 / Kernel 5.15.178) 提权研究归档

归档日期：2026-09-15
设备：vivo S18 (PD2323 / V2323A)，高通 SM7550 (Snapdragon 7 Gen 3)
内核：5.15.178-g0f1e91e908f4-dirty
系统：PD2323_A_16.2.9.0.W10 (OriginOS 6 / Android 16)
SPL：2026-05-01
BL：未解锁（ro.boot.verifiedbootstate=green）
权限：uid=2000(shell)，SELinux enforcing

本仓库整合了过去数月对 vivo S18 的完整研究，修正了此前几个仓库中的多处错误偏移，并保留了所有实测数据。建议先阅读勘误表，再阅读其他章节。

---

⚠️ 勘误表（优先阅读）

此前几个仓库中存在多组错误偏移，如被直接复制使用会导致内核立即 panic 并 bootloop。以下逐条纠正：

项 错误值（旧仓库） 正确值 错误影响
KASLR slide 0x2080ae40 0x20800000 所有 text_addr() 计算偏移 0xae40，指向非法地址
physmap 基址 0xffffffc000000000 0xffffff8800000000 data_addr() 全部错误
selinux_state 运行时 0xffffffc00310c710 0xffffff880310c710 W1 写到内核代码段，秒 panic
TASK_CRED_OFF 0x600 0x798（real_cred 为 0x790） 改错字段，无效或写坏
INIT_CRED_ADDR 0xffff80002a11c2a0 静态 0xffffffc00ae79ca8 + slide 地址落在错误地址空间
MODPROBE_PATH_ADDR 0xffff80002a11c2a0（与 INIT_CRED 相同，明显错误） 需要单独从 System.map 提取 完全无效
SWAPPER_PG_DIR_OFF 0x1755000 0x2a85000（0xffffffc00aa85000 - 0xffffffc008000000） 定位错误页表
rt_mutex_waiter 布局 6.6 版（pi_tree@0x28） 5.15 版（pi_tree@0x18） 所有 fake_waiter 字段错位

关键说明：

1. 0x2080ae40 不是 2MB 对齐（低 21 位 0xae40 ≠ 0）。ARM64 KASLR 粒度是 2MB，这个值不可能是 slide。我们从 kaslr_early_init 反汇编里读到 and x11, x8, #0x1fffff 确认。
2. 0xffffffc0... 是内核镜像区，不是 physmap 区。0xffffff88... 才是 physmap。两者属于不同地址空间，混用会导致物理语义错误。
3. 0xffff8000... 是标准 ARM64 physmap 基址，但 S18 用的是 0xffffff88...（高通/Android 特有）。旧值明显从别的架构或内核版本抄来。
4. 旧仓库里“多次重启 KASLR 稳定在 0x2080ae40”的观察，结果是对的（KASLR 确实固定），但数值是错的——那是因为 crash 位置巧合，不是真正的 slide。

---

目录

1. 设备信息
2. 正确地址空间
3. 全局符号表
4. cfi_jt 桩地址
5. 结构体偏移
6. 栈布局
7. 内核配置
8. 系统限制实测
9. CVE-2026-43499 死路清单
10. CVE-2026-64560 分析（旧仓库整合）
11. 其他 CVE 适用性
12. OEM 攻击面数据（旧仓库整合）
13. PAC 绕过 gadget
14. prepare_good_kernel_page 失效数据
15. 核心防御矩阵
16. 结论
17. 相关仓库

---

1. 设备信息

项目 值
机型 vivo S18 / PD2323 / V2323A
SoC 高通 SM7550 (Snapdragon 7 Gen 3)
内核 5.15.178-g0f1e91e908f4-dirty
系统 PD2323_A_16.2.9.0.W10 (OriginOS 6 / Android 16)
SPL 2026-05-01
BL 未解锁（ro.boot.flash.locked=1，verifiedbootstate=green）
SELinux enforcing
可用权限 uid=2000(shell)
pid_max 32768
RLIMIT_NPROC 43424
RLIMIT_NOFILE 32768

---

2. 正确地址空间

所有数据从 boot.img 提取的 vmlinux（59 MB，/vol2/1000/编译/vmlinux）+ System.map 反汇编确认。

项 值 来源
KIMAGE_TEXT_BASE 0xffffffc008000000 target.h
_stext 0xffffffc008010000 System.map
P0_PAGE_OFFSET（physmap 基址） 0xffffff8800000000 从 KernelSnitch leaked 反推
P0_PHYS_OFFSET 0x80000000 target.h
P0_KERNEL_PHYS_LOAD 0x80000000 target.h
KASLR_SLIDE 0x20800000（2MB 对齐） kaslr_early_init 反汇编
KASLR_ALIGN 0x200000 同上

p0_data_alias 正确形式：

```c
off  = image_addr - KIMAGE_TEXT_BASE;
phys = P0_KERNEL_PHYS_LOAD + off;
return (phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET;
```

kaslr_early_init 关键指令（反汇编）：

```asm
and  x11, x8, #0x1fffff         ; 低 21 位掩码 = 2MB 对齐
and  x10, x8, #0x1fffe00000     ; 位 21-36
and  x9,  x9, #0xfffffffffffff000 ; 4KB 对齐
```

---

3. 全局符号表

```
_stext                  0xffffffc008010000
prepare_kernel_cred     0xffffffc0081ada44
commit_creds            0xffffffc0081ae63c
init_cred               0xffffffc00ae79ca8
init_task               0xffffffc00aec0cc0
root_task_group         0xffffffc00afd8b40
selinux_state           0xffffffc00b10c710
nfulnl_logger           0xffffffc00ad32260
loggers[0][1]           0xffffffc00ad321b0
random_boot_id.data     0xffffffc00ad31260
anon_pipe_buf_ops       0xffffffc00a12d930
kmalloc_caches          0xffffffc00a30e9f0
swapper_pg_dir          0xffffffc00aa85000
ashmem_fops             0xffffffc00a2ac1e8
ashmem_misc             0xffffffc00af0fa30
per_cpu_offset          0xffffffc00acf8000

configfs_read_iter      0xffffffc008705fa0
configfs_write_iter     0xffffffc008706234
configfs_bin_read_iter  0xffffffc008706798
configfs_bin_write_iter 0xffffffc008706ae0
ashmem_ioctl            0xffffffc0091e1a68
compat_ashmem_ioctl     0xffffffc0091e210c
ashmem_mmap             0xffffffc0091e216c
ashmem_open             0xffffffc0091e2460
ashmem_release          0xffffffc0091e2508
ashmem_show_fdinfo      0xffffffc0091e2598
rb_erase                0xffffffc008af2cec
rt_mutex_adjust_prio_chain  0xffffffc00983f3d8
futex_wait_requeue_pi   0xffffffc0082ca07c
core_sys_select         0xffffffc008608d6c
dma_buf_poll            0xffffffc008d93078
posix_cpu_timer_del     0xffffffc0082b48c8
posix_cpu_timer_create  0xffffffc0082b3e34
posix_cpu_timer_set     0xffffffc0082b4238
posix_cpu_timer_get     0xffffffc0082b4c60
run_posix_cpu_timers    0xffffffc0082b27e8
task_work_add           0xffffffc0081a139c
task_work_run           0xffffffc0081a19c4
```

swapper_pg_dir 偏移（修正旧值）：

```c
SWAPPER_PG_DIR_OFF = 0xffffffc00aa85000 - 0xffffffc008000000
                   = 0x2a85000     // 正确
                   // 不是旧仓库里的 0x1755000
```

---

4. cfi_jt 桩地址

kCFI 状态：无 __kcfi_typeid_ 符号，非 kCFI inline 模式。

但有 CFI 范围检查，vfs_ioctl 调用 file->f_op->unlocked_ioctl 前：

```asm
ldr  x8, [x8, #80]              ; slot = f_op->unlocked_ioctl
sub  x9, x8, #0xffffffc009829b18
ror  x9, x9, #3
cmp  x9, #0x89                  ; 表段大小 137 槽
b.cs __cfi_slowpath_diag
blr  x8
```

伪造 fops 表的槽必须落在 [0xffffffc009829b18, +0x89*8) 内，即必须填 .cfi_jt 桩。

```
configfs_read_iter.cfi_jt       0xffffffc00980f9e0   off=0x180f9e0
configfs_write_iter.cfi_jt      0xffffffc00980f9e8   off=0x180f9e8
configfs_bin_read_iter.cfi_jt   0xffffffc00980f9f0   off=0x180f9f0
configfs_bin_write_iter.cfi_jt  0xffffffc00980f9f8   off=0x180f9f8
ashmem_ioctl.cfi_jt             0xffffffc009829e78   off=0x1829e78
compat_ashmem_ioctl.cfi_jt      0xffffffc009829e80   off=0x1829e80
rb_erase.cfi_jt                 0xffffffc0097f4270
```

桩结构（8 字节）：

```asm
bti  c
b    <real_function>
```

---

5. 结构体偏移

5.1 task_struct（5.15）

字段 偏移
real_cred 0x790
cred 0x798
comm 0x7a8
prio 0x7c
normal_prio 0x358
thread_pid 0x640
signal 0x7f0
seccomp 0x868
pi_lock 0x884
pi_waiters 0x890
pi_top_task 0x8a0
pi_blocked_on 0x8b0

注意：旧仓库里的 TASK_CRED_OFF = 0x600 是错的。我们从 commit_creds 反汇编确认是 0x798。

5.2 cred

字段 偏移
uid / gid 0x04 / 0x08
suid / sgid 0x0c / 0x10
euid / egid 0x14 / 0x18
fsuid / fsgid 0x1c / 0x20
securebits 0x24
cap_inheritable 0x28
cap_permitted 0x30
cap_effective 0x38
cap_bset 0x40
cap_ambient 0x48

5.3 rt_mutex_waiter（5.15 布局，大小 0x58）

```
+0x00  tree_entry.parent_color
+0x08  tree_entry.rb_right
+0x10  tree_entry.rb_left
+0x18  pi_tree_entry.parent_color
+0x20  pi_tree_entry.rb_right
+0x28  pi_tree_entry.rb_left
+0x30  task
+0x38  lock
+0x40  wake_state (u32) / prio (u32)
+0x44  prio
+0x48  deadline
+0x50  ww_ctx
```

⚠️ 5.15 与 6.6 布局不同！
6.6：tree@0 / prio@0x18 / pi_tree@0x28 / task@0x50 / lock@0x58 / wake@0x60 / ww@0x68
从 6.6 的 exploit 复制过来的 payload 会整体错位。

5.4 file / file_operations

字段 偏移
f_count 0x38
f_op 0x28
private_data 0xd8
f_op->unlocked_ioctl 0x50
f_op->compat_ioctl 0x58
f_op->mmap 0x60
f_op->open 0x70
f_op->release 0x80
f_op->splice_read 0xc0
f_op->show_fdinfo 0xe0

---

6. 栈布局

定义 K = syscall 入口 sp（kernel_top_sp）。

6.1 futex 链

```
__arm64_sys_futex         sub sp, sp, #0xa0     x29 = sp+0x40
  bl do_futex
  do_futex                sub sp, sp, #0xd0     x29 = sp+0x70
    bl futex_wait_requeue_pi
    futex_wait_requeue_pi sub sp, sp, #0x1c0     x29 = sp+0x160
                          rt_waiter = x29 - 0x90
                                    = K - 0x260
```

6.2 pselect 链

```
__arm64_sys_pselect6      sub sp, sp, #0xa0     x29 = sp+0x40
  bl core_sys_select
  core_sys_select         sub sp, sp, #0x1c0     x29 = sp+0x160
                          bits = sp + 0x50
                               = K - 0x210
```

6.3 差距

```
rt_waiter = K - 0x260
bits      = K - 0x210
差 = 0x50
```

这是 S18 上 CVE-2026-43499 无法利用的根本原因 —— 编译产物决定，无法通过参数调整修复。

6.4 其他 syscall 栈深实测

syscall 缓冲区 距 rt_waiter 结构 可用性
pselect6 K-0x210 0x50 fd_set 8B ❌
select K-0x1f0 0x70 fd_set 8B ❌
compat_pselect6_time64 K-0x250 0x10 32 位字高 32 位恒 0 ❌
sendmsg K-0x2d0 超出 msghdr ❌
recvmsg K-0x1b0 0xb0 msghdr ❌
rt_sigreturn K-0x90 0x1d0 sigcontext ❌
ppoll K-0x300 覆盖 pollfd 48 位可控 ❌
io_uring_enter — 深度不够 无栈拷贝 ❌

6.5 rb_erase 写路径（反汇编确认）

```asm
rb_erase  @ 0xffffffc008af2cec

ldp  x8, x9, [x0, #8]           ; x8 = node->rb_right, x9 = node->rb_left
cbz  x9, 0x2d3c                 ; rb_left == 0 → 走这里
...
0x2d3c:
ldr  x9, [x0]                   ; parent_color
and  x10, x9, #~3               ; parent = parent_color & ~3
...
ldr  x12, [x11, #16]!           ; x12 = parent->rb_left, x11 = parent+16
sub  x13, x11, #0x8             ; x13 = parent+8
cmp  x12, x0                    ; parent->rb_left == node?
csel x11, x11, x13, eq          ; 相等→parent+16, 否则→parent+8
str  x8, [x11]                  ; *(x11) = child
```

结论：

· fake_parent = target - 8
· *(target) = fake_right（低字节 0x00 → enforcing = 0）

---

7. 内核配置

配置 状态 证据
CONFIG_VMAP_STACK y alloc_thread_stack_node / vmap_stack_pg_pool / vmap_stack_alloc_page_atomic
CONFIG_POSIX_CPU_TIMERS_TASK_WORK n posix_cpu_timers_work / handle_posix_cpu_timers 不存在
kCFI（inline typeid） n __kcfi_typeid_ 符号数 = 0
CFI 范围检查 y vfs_ioctl 里 cmp x9, #0x89
PAC（返回地址） y 63630 个 paciasp
CONFIG_PANIC_ON_OOPS y 多次 bootloop 实测
CONFIG_SLAB_FREELIST_HARDENED y 交接文档
CONFIG_RANDOM_KMALLOC_CACHES y 交接文档
CONFIG_ARM64_VA_BITS 39 mov x10, #0x8000000000（2^39）
CONFIG_USER_NS n unshare(CLONE_NEWUSER) 返回 EINVAL

---

8. 系统限制实测

项 结果 errno
/proc/slabinfo 可读 —
/sys/kernel/slab/* 目录 可读 —
/sys/kernel/slab/mm_struct/cpu_partial 拒 EACCES
unshare(CLONE_NEWUSER) 拒 EINVAL
unshare(CLONE_NEWNET) 拒 EPERM
perf_event_open (exclude_kernel=1) 成功 —
perf_event_open (exclude_kernel=0) 拒 EACCES 13
bpf(MAP_CREATE) 拒 EACCES 13
io_uring_setup 成功 fd 返回
io_uring_enter 在 shell 域 SIGSYS（旧仓库实测） —
msgsnd / signalfd SIGSYS（旧仓库实测） —
dmesg / /proc/kallsyms 拒 —

---

9. CVE-2026-43499 死路清单

路径 结果 死因
pselect 栈覆盖 ❌ 差 0x50（编译决定）
compat pselect ❌ 32 位字高 32 位恒 0
select ❌ 差 0x70
sendmsg ❌ 差 0x38
rt_sigreturn ❌ 差 0x1c0
PR_SET_MM_MAP/AUXV ❌ capable(CAP_SYS_RESOURCE) 在前
perf (kernel) ❌ SELinux EACCES
bpf ❌ SELinux EACCES
io_uring ❌ 深度不够 + Seccomp SIGSYS
pipe 页回收 ❌ VMAP_STACK + pool
msg_msg 换 UAF 对象 未试 需重写整个 payload
同对象重用 futex_q ❌（旧仓库实测） SLAB_FREELIST_HARDENED 随机化
公共堆喷占位 futex_q ❌（旧仓库实测） 专用 kmem_cache 物理隔离

总结：355 个 __arm64_sys_* 全部扫过，没有任何一个能字节级覆盖 K-0x260。

---

10. CVE-2026-64560 分析

以下内容整合自 249707737/CVE-2026-64560-Analysis 仓库，漏洞分析部分是真实有效的，但其在 S18 上的适配尝试已失败。

10.1 漏洞概述

字段 内容
CVE ID CVE-2026-64560
标题 posix-cpu-timers: Prevent UAF caused by non-leader exec() race
类型 Use-After-Free（CWE-416），竞态条件
CVSS v3.1 7.8 High
修复提交 920f893f735e92ba3a1cd9256899a186b161928d
引入提交 55e8c8eb2c7b (v5.7, 2020)
报告者 Wongi Lee, Jungwoo Lee

受影响 5.15 分支：5.15.* ~ 5.15.212，修复版本 5.15.213。

S18 状态：内核 5.15.178 < 5.15.213，在受影响范围；SPL 2026-05-01 < 修复日期 2026-07-29，未合入补丁。

10.2 漏洞机理

非 leader 线程 execve() → de_thread() → switch_leader() → 旧 leader release_task() → __exit_signal() 中 old_leader->sighand = NULL。

并行执行的 posix_cpu_timer_del()：

```
p = pid_task(pid, pid_type);         // 查到旧 leader
sighand = lock_task_sighand(p)       // 此时 p->sighand == NULL → 返回 NULL
if (!sighand)
    return 0;                        // 直接返回，不摘链！
free_posix_timer();                  // k_itimer 被释放
```

CLOCK_PROCESS_CPUTIME_ID 定时器在 exec 后被继承，仍挂在 signal->cpu_timers 的 rbtree 上。之后 run_posix_cpu_timers() 遍历 → UAF。

10.3 S18 上的失败原因（旧仓库实测）

攻击手段 结果 死因
add_key 公共 kmalloc-256 堆喷 ❌ k_itimer 在专用 posix_timers_cache，物理隔离
timer_create 同对象重用 ❌ 分配时 __GFP_ZERO 强制清零，无法写入 payload
竞态触发（仅 UAF 本身） ✅ 可稳定触发（该漏洞本身存在）

结论：CVE-2026-64560 的 UAF 本身在 S18 上可触发，但利用链所需的堆喷占位被专用缓存隔离封死。

10.4 与 CVE-2025-38352 的关系

两者都涉及 posix-cpu-timers，但不同的竞态：

CVE 竞态双方 关键条件
CVE-2025-38352 handle_posix_cpu_timers() × posix_cpu_timer_del() CONFIG_POSIX_CPU_TIMERS_TASK_WORK=n
CVE-2026-64560 exec() 中 switch_leader() × timer_delete() 非 leader 线程 exec

S18 上 =n 已确认（posix_cpu_timers_work 符号不存在），两条路径理论上都成立，但利用难度相同。

---

11. 其他 CVE 适用性

CVE 结果 原因
CVE-2025-21479（Adreno GPU） ❌ GPU 固件 v676（已修复）
CVE-2025-48595 ❌ NAS 上的 PoC 是 TraeBot AI 生成，非真实漏洞
CVE-2025-38352（POSIX CPU timers） ⚠️ 配置匹配，5-10% 成功率，唯一未穷尽
CVE-2026-64560（POSIX CPU timers） ⚠️ 可触发，但堆喷被隔离
CVE-2026-46242（Bad Epoll） ❌ 影响 5.15.209+，S18 低于
CVE-2026-46331（pedit COW） ❌ 需 USER_NS
CVE-2026-31431（Copy Fail） ❌ 需 AF_ALG socket
CVE-2026-43501 ❌ 需 USER_NS
CVE-2026-23274 ❌ x86_64 专用
CVE-2026-43499-popsicle ❌ 目标内核 6.12
CVE-2026-68138（qdisc） ❌ 需 USER_NS
CVE-2025-37947（ksmbd） ❌ Android 未启用 ksmbd
CVE-2023-20938（Binder UAF） ❌ 5.15 高通版 offsets_size 校验已变，旧 PoC 无效
dmabuf poll UAF ❌ 已修补（dma_buf_poll 有 f_count 检查）

dmabuf poll UAF 修补证据（dma_buf_poll 反汇编）：

```asm
ffffffc008d930a0:  add  x8, x0, #0x38       ; &file->f_count
ffffffc008d930a4:  ldar x8, [x8]            ; f_count
ffffffc008d930a8:  cbz  x8, +0x124          ; == 0 → 跳过
```

这是补丁的核心逻辑。

---

12. OEM 攻击面数据

12.1 高通 KGSL（Adreno 720）IOCTL 命令码

整合自 249707737/Android-16-SM7550-Kernel-5.15.178-LPE-Research 仓库。

通过 /dev/kgsl-3d0 真机验证可用：

```c
#define IOCTL_KGSL_DRAWCTXT_CREATE 0x13    // 成功：创建 GPU 上下文
#define IOCTL_KGSL_MAP_USER_MEM    0x15    // 成功：GPU 映射
#define IOCTL_KGSL_GPU_COMMAND     0x4A    // 成功：触发 GPU 命令发送
```

SMMU 硬件拦截：即使命令码和偏移正确，向硬件 SMMU 发起 CP_SMMU_TABLE_UPDATE 时，内核返回 Bad address。高通在 5.15 内核开启硬件级 SMMU 防篡改保护，EL0 无法通过软件绕过。

12.2 堆喷对象实测数据

对象 缓存 大小 堆喷效果 能否命中 futex_q
eventpoll_epi eventpoll_epi 128 稳定（5048 → 5474） ❌ 专用池
skbuff_head_cache skbuff_head_cache 256 稳定（9845 → 10041） ❌ 专用池
posix_timers_cache posix_timers_cache 264 无变化 ❌ 专用池
add_key payload kmalloc-256 256 成功分配 ❌ 与 futex_q 物理隔离

关键限制：Kernel 5.15 的 RANDOM_KMALLOC_CACHES + 专用 kmem_cache 把敏感对象与公共池物理隔离。堆喷再成功也无法命中目标。

12.3 Seccomp 沙箱实测

系统调用 shell 域 说明
io_uring_setup SIGSYS（信号 31） 直接终止进程
msgsnd / msgget SIGSYS —
signalfd SIGSYS —
eventfd ✅ 允许 但无法命中目标
timerfd ✅ 允许 同上
userfaultfd ✅ 允许 同上
netlink ✅ 允许 同上
perf_event_open EACCES SELinux 拒
bpf EACCES SELinux 拒

12.4 Fork 分离法（避免看门狗）

旧仓库实测有效的工程技巧。

```
父进程：触发 UAF → 内存破坏 → exit(0)
子进程：继承被破坏的内存 → 完成后续操作 → exit(0)
```

作用：避免"写文件 → 内核执行复杂操作 → 触发 PANIC_ON_OOPS → 10 秒看门狗硬重启"的死循环。

副作用：SELinux 依然拦截 /data/local/tmp/ 下的 SUID 提权（打上 shell_data_file 标签，重启清空）。

---

13. PAC 绕过 gadget

位置：__idmap_text 段（0xffffffc009868000 - 0xffffffc00986890c，RO+X，EL1 运行时常驻映射）。

```
入口：0xffffffc009868020
    movz x0, #0x0, lsl #16
    movk x0, #0x3c5
    msr  spsr_el1, x0        ; SPSR = 0x3c5 = EL0t + DAIF 全屏蔽
    msr  elr_el1, x30        ; ELR = x30（可控制）
    mov  w0, #0xe11
    eret                     ; 无 autiasp
```

用法：ROP 链末尾设 x30 = 用户态 payload 地址，跳 0xffffffc009868020。

⚠️ 注意：

1. SPSR=0x3c5 → EL0 后 DAIF 全屏蔽。用户态 payload 第一件事必须是 execve("/system/bin/sh")。
2. 不经过 ret_to_user 的 need_resched / work_pending 检查，preempt_count 可能脏。execve 会重置。

---

14. prepare_good_kernel_page 失效数据

实测（PREPARE_SLABS=512）：

时刻 objects slabs
baseline ~900 64
fork 16384 后 17092 2691
close(memfd_leak) 后 901 107
未归还 — 43

/proc/slabinfo 关键行：

```
SLAB mm_struct BEFORE sendmsg: mm_struct  901  1716  1024  32  8  : slabdata  107  107  0
```

· objsize=1024，objperslab=32，pagesperslab=8（order-3）
· 与 MM_STRUCT_SZ=0x400、MM_ORDER=3 一致
· active_slabs == num_slabs（107 == 107）

结论：SLUB 把释放的 slab 页挂在 per-CPU partial / node partial，不主动归还 buddy。sendmsg 的 skb 从 buddy 分配拿不到这块页。

base = leaked & ~0x7fff 指向活 mm_struct slab，不是 skb payload。 整个 payload_base = base - 0xe80 偏移计算无效。

PREPARE_SLABS=1024：16384 → 32768 fork，pid_max=32768 用尽，SYSCHK 直接 panic → bootloop。

---

15. 核心防御矩阵

vivo S18 量产固件下的四重物理级别防御：

层级 防御手段 实测效果
第一重（SLAB 层） 专用 kmem_cache + RANDOM_KMALLOC_CACHES + SLAB_FREELIST_HARDENED 公共堆喷绝对无法命中 futex_q / k_itimer；同对象重用被随机化 + __GFP_ZERO 清零
第二重（系统调用层） Seccomp 沙箱 封杀 io_uring / msgsnd / signalfd（SIGSYS）
第三重（内核配置层） CONFIG_USER_NS 未启用 unshare(CLONE_NEWUSER) = EINVAL；现代提权链第一步断
第四重（硬件层） ARM PAC + 高通 SMMU + MTE ROP 触发 autiasp 校验；SMMU 拦截 EL0 物理页表修改；MTE 干扰侧信道
额外 CONFIG_PANIC_ON_OOPS=y 任何 OOPS 秒级重启，无调试窗口
额外 CONFIG_VMAP_STACK=y + vmap_stack_pg_pool 内核栈在 vmalloc 区，pipe 页回收无效

---

16. 结论

S18 (5.15.178) 上所有已知公开提权路径均不可行。

三条独立防线叠加：

1. 编译产物决定：rt_waiter 与 pselect bits 差 0x50，无任何 syscall 能字节级覆盖；
2. SLUB 隔离：专用缓存池 + 随机化 + __GFP_ZERO，堆喷无法命中；
3. KASLR 泄漏全断：perf 内核采样被 SELinux 拒，KernelSnitch 在 MTK 平台不可靠。

其他 CVE 全部排除：

· GPU v676 已修复
· USER_NS 未编译
· AF_ALG 被 SELinux 拒
· ksmbd 无
· dmabuf 已补
· Binder 5.15 高通版校验已变

唯一配置上匹配的替代路径：

· CVE-2025-38352（成功率 5-10%，需数天到数周）
· CVE-2026-64560（同族漏洞，UAF 可触发，但堆喷隔离导致无法利用）

确定性方案：转 6.6 设备（Neo11 Plus / blazer / frankel），IonStack 原版 exploit 直接可用（成功率 70-90%）。

---
18. 相关仓库

· CVE-2026-64560-Analysis —— posix-cpu-timers 非 leader exec 竞争 UAF 分析
· vivo-S18-Binder-Research —— Binder 攻击面
· vivo-S18-SM7550- —— 早期研究归档
· Android-16-SM7550-Kernel-5.15.178-Exploit-Research —— 防御矩阵测绘
· Android-16-SM7550-Kernel-5.15.178-LPE-Research —— 盲测记录
· Android-15-Kernel-5.15-SM7550- —— 早期测试存档
---

各仓库数据勘误汇总

· 所有仓库中出现的 0x2080ae40（KASLR slide）→ 应改为 0x20800000
· 所有仓库中出现的 0xffffffc000000000（physmap 基址）→ 应改为 0xffffff8800000000
· 所有仓库中出现的 TASK_CRED_OFF = 0x600 → 应改为 0x798
· 所有仓库中出现的 INIT_CRED_ADDR = 0xffff80002a11c2a0 → 应改为 0xffffffc00ae79ca8 + KASLR_SLIDE
· 所有仓库中出现的 MODPROBE_PATH_ADDR → 需要单独从 System.map 提取，不是 0xffff80002a11c2a0
· 所有仓库中出现的 SWAPPER_PG_DIR_OFF = 0x1755000 → 应改为 0x2a85000

请勿将上述错误值用于任何新的 exploit 代码。

---

免责声明

本仓库内容仅供安全研究和教育目的。所有数据来自对自己拥有设备的合法研究。请勿将本文档用于非法用途。

---

最后更新：2026-09-15

近期不打算再继续了，等待新的漏洞
