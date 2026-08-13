# 构建指南

chinadns-ng 使用 GNU C11，仅支持 Linux。可以在 Linux 上使用 Make 或 CMake 本机构建，也可以使用 Zig 交叉编译静态 musl 版本。如果需要与 GitHub Release 类似的完整 CPU/ABI 矩阵和 wolfSSL/DoT 版本，建议使用 Docker 构建。

## 选择构建方式

| 方式 | 用途 | 默认输出 |
| --- | --- | --- |
| Make | Linux 本机开发和测试，可选 wolfSSL | `build/chinadns-ng` |
| CMake | 使用 CMake 的 Linux 本机构建，可选 wolfSSL | CMake 构建目录 |
| `tool/cross-build.sh` | 快速生成通用的静态 musl 普通版 | `build/cross/` |
| Docker Release 矩阵 | 生成按 CPU/ABI 优化的普通版、wolfSSL 版和 `wolfssl_noasm` 版 | `build/docker/` |

`tool/cross-build.sh` 和 Docker Release 矩阵的用途不同。前者只生成 12 个通用架构的普通版；后者覆盖 23 个 CPU/ABI 组合，默认生成 47 个可执行文件。

## 获取源码

```bash
git clone https://github.com/zfl9/chinadns-ng
cd chinadns-ng
```

## 使用 Make 本机构建

### 依赖

普通版需要 Linux、GNU Make 和支持 GNU C11 的 C 编译器。已在 Ubuntu 26.04 的 GCC 15 和 Clang 21 上验证。

DoT 是可选功能。构建 wolfSSL 版时还需要 wolfSSL 头文件和库；Debian/Ubuntu 可以安装 `libwolfssl-dev`。

### 常用命令

```bash
# 普通版
make -j

# wolfSSL/DoT 版
make -j WOLFSSL=1

# 使用 Clang
make -j CC=clang

# 删除整个 build/ 目录
make clean
```

普通版默认输出到 `build/chinadns-ng`，wolfSSL 版默认输出到 `build/chinadns-ng+wolfssl`。默认链接方式由本机工具链决定，Makefile 不会自动添加 `-static`。

`make clean` 会删除整个 `build/` 目录，其中可能包含 Zig 交叉编译产物、Docker 导出产物和 `build/.release-cache/`。如果需要保留这些文件，请不要直接执行该命令。

### Make 变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CC` | `cc` | C 编译器，例如 `gcc`、`clang` 或 `musl-gcc` |
| `CPPFLAGS` | 空 | 额外的预处理参数 |
| `CFLAGS` | `-O2 -g` | 额外的 C 编译参数 |
| `LDFLAGS` | 空 | 额外的链接参数 |
| `LDLIBS` | 空 | 额外的链接库 |
| `WOLFSSL` | 未设置 | 设为 `1` 时启用 wolfSSL/DoT |
| `MUSL` | 未设置 | 设为 `1` 时定义项目的 `MUSL` 宏 |
| `TARGET` | 视构建变体而定 | 覆盖可执行文件的输出路径 |

`MUSL=1` 只会定义编译宏，不会自动选择 musl 工具链或启用静态链接。如果需要可移植的静态 musl 产物，优先使用 Zig 交叉编译脚本或 Docker Release 矩阵。

## 使用 CMake 本机构建

```bash
# 普通版
cmake -S . -B build-cmake
cmake --build build-cmake -j

# wolfSSL/DoT 版
cmake -S . -B build-cmake-wolfssl -DENABLE_WOLFSSL=ON
cmake --build build-cmake-wolfssl -j
```

`ENABLE_WOLFSSL=ON` 时，CMake 会在系统库路径中查找 `wolfssl`。如果未找到，配置阶段会失败。CMake 输出位于 `-B` 指定的构建目录。

启用 wolfSSL 只会为可执行文件加入 DoT 支持。运行时的证书校验仍由 `--cert-verify` 和 `--ca-certs` 选项控制。

## 运行测试

测试需要 Linux 和 Python 3。

```bash
# 普通版端到端测试
make check

# DoT 与证书校验测试，需要 wolfSSL 和 OpenSSL
make check-wolfssl

# ipset 裁决与 add-IP 测试，需要 root 权限和 ipset
sudo make check-ipset
```

## 使用 Zig 快速交叉编译

`tool/cross-build.sh` 把本机安装的 `zig cc` 作为 C 交叉编译器，生成 `-O2 -static` 的 musl 普通版。Zig 只用作工具链，可执行文件不依赖 Zig 语言运行时。该脚本不编译 wolfSSL，也不区分同一架构下的 CPU 级别。

### 构建全部通用目标

```bash
./tool/cross-build.sh
```

产物位于 `build/cross/`。默认目标为：

```text
x86-linux-musl
x86_64-linux-musl
arm-linux-musleabi
arm-linux-musleabihf
aarch64-linux-musl
mips-linux-musleabi
mips-linux-musleabihf
mipsel-linux-musleabi
mipsel-linux-musleabihf
mips64-linux-muslabi64
mips64el-linux-muslabi64
riscv64-linux-musl
```

### 构建指定通用目标

将一个或多个 Zig 目标三元组（target triple）作为位置参数传给脚本：

```bash
./tool/cross-build.sh \
  x86_64-linux-musl \
  mipsel-linux-musleabi
```

可以通过环境变量覆盖 Zig 命令和输出目录：

```bash
ZIG=/opt/zig/zig OUT=build/custom-cross \
  ./tool/cross-build.sh aarch64-linux-musl
```

## 使用 Docker 构建 Release 矩阵

### 特点与依赖

Docker 构建会：

- 从 `alpine:latest` 的软件仓库安装当前的 Zig；
- 使用 Zig 作为 C 交叉编译工具链；
- 生成静态 musl ELF，不需要目标设备提供动态 C 库；
- 在需要时下载并按目标架构静态编译 wolfSSL；
- 使用 Docker BuildKit 缓存 Zig、wolfSSL 源码和各目标的中间产物。

需要安装 Docker，并允许构建过程访问 Alpine 软件仓库和 GitHub。构建容器可以运行在 amd64 或 arm64 Linux 环境中；主机使用 Docker Desktop 或其他 Linux 虚拟化环境也可以构建。生成的目标架构与构建环境的架构无关。

Dockerfile 不固定 Zig 版本；每次重新获取 `alpine:latest` 时，都可能安装到更新的 Zig。构建日志会输出实际的 `zig version`。这种方式优先获取新工具链，不保证不同时间的构建完全可重现。

### 构建完整矩阵

```bash
docker build \
  --target artifacts \
  --output type=local,dest=build/docker \
  .
```

`type=local` 会将 `artifacts` 阶段的内容直接写入宿主机目录。如果要保留多组不同筛选条件的产物，应为每次构建使用不同的 `dest`，避免与目录中的旧文件混合。

默认生成：

- 23 个不含 DoT 的普通版；
- 23 个 wolfSSL/DoT 版；
- 1 个 AArch64 v8a `wolfssl_noasm` 版；
- 1 份覆盖上述 47 个可执行文件的 `SHA256SUMS`。

### 完整目标矩阵

`TARGETS` 使用“输出目标标识 + `@` + CPU”作为精确选择器。下表列出了全部 23 个组合。

| 架构 | `TARGETS` 精确选择器 | 浮点 ABI/说明 |
| --- | --- | --- |
| AArch64 | `aarch64-linux-musl@generic+v8a` | ARMv8-A |
| AArch64 | `aarch64-linux-musl@generic+v9a` | ARMv9-A |
| ARM | `arm-linux-musleabi@generic+v5t+soft_float` | ARMv5T 软浮点 |
| ARM | `arm-linux-musleabi@generic+v5te+soft_float` | ARMv5TE 软浮点 |
| ARM | `arm-linux-musleabi@generic+v6+soft_float` | ARMv6 软浮点 |
| ARM | `arm-linux-musleabi@generic+v6t2+soft_float` | ARMv6T2 软浮点 |
| ARM | `arm-linux-musleabi@generic+v7a` | ARMv7-A 软浮点 |
| ARM | `arm-linux-musleabihf@generic+v7a` | ARMv7-A 硬浮点 |
| x86 | `i386-linux-musl@i686` | i686 |
| x86 | `i386-linux-musl@pentium4` | Pentium 4 |
| MIPS | `mips-linux-musl@mips32` | MIPS32 大端硬浮点 |
| MIPS | `mips-linux-musl@mips32+soft_float` | MIPS32 大端软浮点 |
| MIPS64 | `mips64-linux-musl@mips64` | MIPS64 大端硬浮点 |
| MIPS64 | `mips64-linux-musl@mips64+soft_float` | MIPS64 大端软浮点 |
| MIPS64el | `mips64el-linux-musl@mips64` | MIPS64 小端硬浮点 |
| MIPS64el | `mips64el-linux-musl@mips64+soft_float` | MIPS64 小端软浮点 |
| MIPSel | `mipsel-linux-musl@mips32` | MIPS32 小端硬浮点 |
| MIPSel | `mipsel-linux-musl@mips32+soft_float` | MIPS32 小端软浮点 |
| RISC-V 64 | `riscv64-linux-musl` | `baseline_rv64` |
| x86_64 | `x86_64-linux-musl@x86_64` | x86-64-v1 |
| x86_64 | `x86_64-linux-musl@x86_64_v2` | x86-64-v2 |
| x86_64 | `x86_64-linux-musl@x86_64_v3` | x86-64-v3 |
| x86_64 | `x86_64-linux-musl@x86_64_v4` | x86-64-v4 |

### 筛选架构和 CPU

`TARGETS` 的值是一个或多个以空白分隔的子字符串。构建脚本将每个值与表中的“`target@CPU`”进行子字符串匹配。未指定 `TARGETS` 时构建全部组合。

只构建 x86_64 的 v1、v2、v3 和 v4：

```bash
docker build \
  --target artifacts \
  --build-arg TARGETS=x86_64-linux-musl \
  --output type=local,dest=build/docker-x86_64 \
  .
```

只构建 AArch64 v8a：

```bash
docker build \
  --target artifacts \
  --build-arg 'TARGETS=aarch64-linux-musl@generic+v8a' \
  --output type=local,dest=build/docker-aarch64-v8a \
  .
```

同时构建 AArch64 和 RISC-V 64 的全部变体：

```bash
docker build \
  --target artifacts \
  --build-arg 'TARGETS=aarch64-linux-musl riscv64-linux-musl' \
  --output type=local,dest=build/docker-arm-riscv \
  .
```

使用宽泛的子字符串会匹配多个组合。例如 `TARGETS=mips` 会匹配 MIPS、MIPSel、MIPS64 和 MIPS64el 的全部大小端与浮点 ABI。如果需要单一组合，应使用上表的完整选择器。

### 选择普通版或 wolfSSL 版

`FLAVORS` 是以空白分隔的构建变体列表，支持下列值：

| 值 | 产物 | 说明 |
| --- | --- | --- |
| `plain` | `chinadns-ng@...` | 不含 wolfSSL，不支持 DoT |
| `wolfssl` | `chinadns-ng+wolfssl@...` | 静态链接 wolfSSL，支持 DoT |

默认值是 `plain wolfssl`。`wolfssl_noasm` 不是可直接传给 `FLAVORS` 的值；当 `FLAVORS` 包含 `wolfssl`、`NOASM=1` 且选中 AArch64 v8a 时，构建脚本会额外生成该版本。

`wolfssl_noasm` 会关闭 wolfSSL 的 AArch64 专用汇编加速，适用于该加速实现不兼容的设备。`NOASM` 对 `FLAVORS=plain` 没有影响。

只构建全部普通版：

```bash
docker build \
  --target artifacts \
  --build-arg FLAVORS=plain \
  --output type=local,dest=build/docker-plain \
  .
```

只构建 MIPSel 软浮点 wolfSSL 版：

```bash
docker build \
  --target artifacts \
  --build-arg 'TARGETS=mipsel-linux-musl@mips32+soft_float' \
  --build-arg FLAVORS=wolfssl \
  --build-arg NOASM=0 \
  --output type=local,dest=build/docker-mipsel-soft-wolfssl \
  .
```

构建 AArch64 v8a 普通版和 wolfSSL 版，但不生成 `wolfssl_noasm` 版：

```bash
docker build \
  --target artifacts \
  --build-arg 'TARGETS=aarch64-linux-musl@generic+v8a' \
  --build-arg NOASM=0 \
  --output type=local,dest=build/docker-aarch64-v8a \
  .
```

### Docker 构建参数

| 构建参数 | 默认值 | 说明 |
| --- | --- | --- |
| `TARGETS` | 空 | 目标筛选器；留空时构建完整矩阵 |
| `FLAVORS` | `plain wolfssl` | 构建普通版、wolfSSL 版或两者 |
| `NOASM` | `1` | 是否额外构建 AArch64 v8a `wolfssl_noasm` 版 |
| `WOLFSSL_VERSION` | `5.8.2` | wolfSSL 版本，对应 `v<version>-stable` 标签 |

`WOLFSSL_VERSION` 必须对应 wolfSSL GitHub 仓库中存在的 `v<version>-stable` 标签。不同 wolfSSL 版本的 `configure` 选项可能变化；当前默认版本已通过完整矩阵验证，覆盖版本后需要自行确认兼容性。

覆盖 wolfSSL 版本的示例：

```bash
docker build \
  --target artifacts \
  --build-arg WOLFSSL_VERSION=5.8.2 \
  --output type=local,dest=build/docker \
  .
```

### 产物数量

| 参数 | 可执行文件数量 |
| --- | ---: |
| 默认完整矩阵 | 47 |
| `FLAVORS=plain` | 23 |
| `FLAVORS=wolfssl` | 24 |
| `FLAVORS=wolfssl NOASM=0` | 23 |

筛选 `TARGETS` 后，实际数量取决于匹配的 CPU/ABI 组合数和构建变体。`wolfssl_noasm` 只会为 AArch64 v8a 额外生成一个文件。

### 产物命名

普通版和 wolfSSL 版分别使用以下格式：

```text
chinadns-ng@<target>@<cpu>@<mode>
chinadns-ng+wolfssl@<target>@<cpu>@<mode>
chinadns-ng+wolfssl_noasm@<target>@<cpu>@<mode>
```

例如：

```text
chinadns-ng@x86_64-linux-musl@x86_64_v3@fast+lto
chinadns-ng+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto
chinadns-ng+wolfssl_noasm@aarch64-linux-musl@generic+v8a@fast+lto
```

大部分产物使用 `-O3 -flto`，文件名以 `@fast+lto` 结尾。已验证的 Alpine Zig 0.16 无法为 MIPS64/MIPS64el 软浮点目标完成 LTO 链接，因此下列 4 个产物使用 `-O3` 并以 `@fast` 结尾：

- MIPS64 大端软浮点普通版和 wolfSSL 版；
- MIPS64 小端软浮点普通版和 wolfSSL 版。

### 构建验证

每个可执行文件生成后，脚本会：

1. 使用 `readelf` 确认输出是有效的 ELF。
2. 检查程序头，确认不存在动态解释器。
3. 对所有 MIPS 软浮点产物检查 `FP ABI: Soft float` 标志。
4. 在输出目录生成 `SHA256SUMS`。

可以在 Linux 上进一步校验所有产物：

```bash
cd build/docker
sha256sum -c SHA256SUMS
```

### 构建可复用的工具链镜像

Dockerfile 的默认目标是可复用的工具链镜像：

```bash
docker build -t chinadns-ng-builder .
```

挂载源码目录后构建完整矩阵：

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/src \
  chinadns-ng-builder
```

镜像名称后的位置参数会覆盖 `TARGETS`：

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/src \
  chinadns-ng-builder \
  'aarch64-linux-musl@generic+v8a'
```

也可以通过环境变量控制构建变体、并行数、输出目录和缓存目录：

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/src \
  -e FLAVORS=plain \
  -e NOASM=0 \
  -e JOBS=4 \
  -e OUT=build/release-aarch64-v8a \
  -e CACHE_DIR=build/.release-cache \
  chinadns-ng-builder \
  'aarch64-linux-musl@generic+v8a'
```

挂载源码目录时，默认产物位于宿主机的 `build/release/`，默认缓存位于 `build/.release-cache/`。如果需要分别保留不同筛选条件的结果，应为每次构建设置不同的 `OUT`，避免新旧产物混合。

### 缓存行为

使用 `--target artifacts` 构建时，BuildKit 将 `/build-cache` 作为持久缓存挂载。首次构建 wolfSSL 矩阵较慢，因为每个目标与 CPU 组合都需要单独编译静态 wolfSSL。相同参数的后续构建会复用这些中间产物。

使用可复用工具链镜像时，缓存位于源码目录中的 `build/.release-cache/`。`WOLFSSL_VERSION`、目标、CPU、浮点 ABI 和 `wolfssl_noasm` 选项都是 wolfSSL 缓存键的一部分。

### 兼容性处理

构建镜像包含两项针对当前 Zig 工具链的兼容处理：

- MIPS 软浮点包装器会把 `-msoft-float` 传递给 Zig 内部的 Clang 调用，并在构建后检查 ELF ABI。
- ARMv5 目标会链接 Linux ARM EABI 原子操作兼容实现。

这些处理由 Dockerfile 和 `tool/release-build.sh` 自动启用，不需要额外构建参数。

### 常见问题

#### Docker 构建与 `--privileged` 有关吗？

无关。编译不需要 `--privileged`。README 中的 `NET_ADMIN`、`--network host` 或 `--privileged` 说明只适用于在容器中运行 chinadns-ng，并让它操作 ipset/nftset 的场景。

#### 为什么完整矩阵的首次构建很慢？

23 个 CPU/ABI 组合中的每个 wolfSSL 版本都需要一份匹配目标的静态 wolfSSL 库。后续构建会复用 BuildKit 或 `build/.release-cache/` 中的缓存。

#### 为什么没有生成任何文件？

检查 `TARGETS` 是否至少匹配上表中的一个选择器，并检查 `FLAVORS` 是否包含 `plain` 或 `wolfssl`。如果同时指定多个 `TARGETS`，必须将整个值放在引号中。

#### 为什么无法在构建主机上直接运行某个产物？

交叉编译产物只能在匹配的 CPU 架构和 ABI 上直接运行。应将它复制到目标设备测试，或使用支持相应架构和 ABI 的模拟器。

#### 如何确认实际使用的 Zig 版本？

Docker 镜像构建时会执行 `zig version`，版本号会出现在 `docker build` 日志中。如果对工具链可重现性有严格要求，需要另行固定 Alpine 镜像 digest 和 Zig 软件包版本；当前 Dockerfile 按需求优先使用 Alpine 提供的当前版本。
