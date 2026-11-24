# `game_scarlett_master.exe` 反编译 / 静态分析报告

**生成时间**：2026-11-24 14:0x（无人值守阶段）
**对象**：`C:\boottest\game_scarlett_master.exe`（120,181,760 B / 114.61 MiB）
**原始数据**：`game_scarlett_pe_static.txt`（`pe_static_analysis.py` 解析结果）
**方法边界**：本机无 Ghidra/IDA；镜像含 **299,257 个函数**（`.pdata`），全量反编译不现实且无符号。因此采用**结构化 PE 解析 + 定点反汇编（cdb）+ 人工还原伪代码**，重点覆盖当前启动调试实际走到的函数。静态分析用于**佐证常量、函数边界与调用形状**，动态调试（cdb）仍是主线。

---

## 一、PE 结构（为什么必须手动映射）

| 项 | 值 |
|---|---|
| 机器 | `0x8664` AMD64（**x86-64 原生代码，无需指令翻译**） |
| 入口 | RVA `0x56a1ec8` → VA `0x1456a1ec8` |
| ImageBase | `0x140000000` |
| SizeOfImage | `0xb06d000`（**176.4 MiB**，而文件只有 114.61 MiB → 存在大量零填充 `.data/.bss`） |
| 节区数 | 10 |
| 数据目录 | 16；EXPORT / IMPORT / EXCEPTION / BASERELOC / DEBUG / TLS / LOAD_CONFIG / IAT |

| 节区 | RVA | VSize | RawSize | 说明 |
|---|---|---|---|---|
| `.text` | `0x1000` | `0x05f3f966` | `0x05f3fa00` | 代码，约 99.8 MB |
| `.rdata` | `0x05f41000` | `0x008a0c0c` | `0x008a0e00` | 常量、字符串、GUID、vtable |
| `.data` | `0x067e2000` | `0x043ec398` | **`0x00622e00`** | **VSize 远大于 RawSize → 大量零填充全局区** |
| `.pdata` | `0x0abcf000` | `0x36cbac` | `0x36cc00` | 299,257 个 `RUNTIME_FUNCTION` |
| `.tls` | `0x0af3d000` | `0x1481` | `0x1600` | 静态 TLS 模板 |
| `.reloc` | `0x0af41000` | `0x12a350` | `0x12a400` | 重定位 |
| `.retplne` / `.voltbl` / `.xbld` | — | 很小 | — | Xbox 编译器辅助节 |

> **`.data` 的 VSize(71 MB) ≫ RawSize(103 MB? 实际 0x622e00=6.4 MB)** 这一事实解释了为什么 `0x148759d00`（全局 device 指针）、`0x1475e72a0`/`0x1475e7300`（命令列表/allocator 全局数组）、`0x1498f84ac` 等地址**在文件里读不到字节**——它们在运行时零填充区。这直接印证了之前 cdb 里"对象全 0"的断言现场。

## 二、导入表：68 个 DLL / 587 个导入

运行时日志中的 `shim=32 host=455 unimplemented=100` 与静态表一致。重点 DLL：

| DLL | 导入数 | 关键函数 |
|---|---|---|
| `MSVCP140.dll` | 113 | CRT C++ 运行时 |
| `api-ms-win-crt-*` 合计 | ~158 | CRT（math 41 / stdio 29 / string 31 / runtime 25 …） |
| `libHttpClient.GDK.dll` | 38 | 全部未实现（联网，离线启动不影响） |
| `Bink2Scarlett.dll` | 23 | 视频解码，单测已用真实流跑通 |
| `xmem.dll` | **12** | `XMemAlloc` / `XMemVirtualAlloc` / **`XMemAllocatePhysicalPages`** / `XMemGetWorkingSetStatistics` 等 |
| `AcpHal.dll` | 9 | APU（音频），未实现 |
| `XboxBvhBuilder.dll` | 7 | 光追加速结构，未实现 |
| `chad.dll` / `xapu.dll` | 5 / 5 | 音频，未实现 |
| `d3d12_xs.dll` | **3** | `D3D12ConfigureVirtualMemoryX`、`D3D12SerializeVersionedRootSignature`、`D3D12XboxCreateDevice` |
| `XCRDAPI.dll` | **1** | `DStorageGetFactory` |
| `api-ms-win-core-file-l1-1-0.dll` | 22 | `CreateFileW` / `GetFileAttributesW` / `FindFirstFileW` …（已 shim） |
| `api-ms-win-core-libraryloader-l1-2-0.dll` | 8 | `GetProcAddress` / `LoadLibraryExW` …（已 shim） |

> **导入表几乎不含 `d3d12_xs` 的其它函数**——设备/命令列表/队列全部通过 `D3D12XboxCreateDevice` 返回的 **COM 虚表**调用。这正是为什么调试重点在 **vtable slot 重映射**，而不是补导入。

## 三、TLS 目录（此前崩溃的根源）

| 字段 | 值 |
|---|---|
| RawDataStart / End | `0x14af3d000` / `0x14af3e480`（模板 0x1480 B） |
| **AddressOfIndex** | `0x146e08b2c`（→ `_tls_index`） |
| CallBacks | `0x146791a18` → **2 个 TLS 回调**：`0x1455dd4f4`、`0x1455e2ebc` |
| Characteristics | `0x500000` |

**静态结论**：EXE 自带静态 TLS + 2 个回调，且 MSVC 把 EXE 的 TLS 访问编译为 `mov rax, gs:[58h]; mov rax, [rax]`（**硬编码 slots[0]**）。这从文件结构上解释了 11-24 上午的 TLS 槽位错位根因：把游戏块装进辅助 DLL 的 index 7、或改写 `_tls_index` 变量都无效，**必须按镜像 index 0 安装**，同时用 `/Zc:threadSafeInit-` 与 `TlsAlloc` 槽保护宿主自己的 TLS 块。

## 四、`.pdata` 与当前调试的函数边界

| 我们关心的地址 | 所属函数（RVA） | 大小 |
|---|---|---|
| `0x142478b30`（命令列表池初始化） | `0x2478440..0x2479682` | `0x1242`（4,674 B） |
| `0x142478dc7`（slot 78/79 调用） | 同上 | 同一个大函数 |
| `0x142237178`（`appdata0.rpf` 断言） | `0x2236e00..0x22371bd` | `0x3bd`（957 B） |
| 入口 `0x1456a1ec8` | `0x56a1ec8..0x56a1eda` | `0x12`（跳转桩） |

## 五、关键字符串 / 常量定位（静态佐证动态调试）

| 内容 | VA | 段 | 意义 |
|---|---|---|---|
| `G:\` | `0x141dad273` | **`.text`** | **确认游戏用 `G:\` 盘符寻址 `GAME:` 卷**——正是 `file_system.cpp` 需要支持 `g:` 映射的原因 |
| `xgameruntime.dll` (UTF-16) | `0x14678e9a0` | `.rdata` | 运行时 `LoadLibraryW` 目标 |
| `QueryApiImpl` | `0x14678d8b8` | `.rdata` | GDK 6 个 `GetProcAddress` 名字之一 |
| `InitializeApiImplEx2` | `0x14678e1a8` | `.rdata` | 同上 |
| `XErrorReport` | `0x14678d550` | `.rdata` | 此前缺失、已补的导出 |
| `DStorageGetFactory` | `0x146797388` | `.rdata` | 此前缺失、已补 |
| `XMemAllocatePhysicalPages` | `0x146796644` | `.rdata` | 此前缺失、已补 |
| `d3d12_xs.dll` / `XCRDAPI.dll` | `0x146798929` / `0x146798ba4` | `.rdata` | 导入 DLL 名 |
| `D3D12XboxCreateDevice` | `0x146796b3a` | `.rdata` | 设备创建 |
| `game_scarlett_master.exe` | `0x146791a78` | `.rdata` | 导出表附近 |

**两个 GUID（`.rdata`，静态读回，纠正了此前的字节序误读）**：

| VA | GUID | 用途 |
|---|---|---|
| `0x1461e0668` | **`{C3827890-4024-474C-98CF-645B51DC4874}`** | Xbox graphics command list IID（device slot 73 的 `arg5`） |
| `0x1461e0658` | **`{6102DEE4-AF59-4B09-B999-B44D73F09B24}`** | Xbox **command allocator** IID（device slot 9 的 `arg3`） |

> 13:43 的诊断日志实测 `asked IID {C3827890-4024-474C-98CF-645B51DC4874}`，与此处静态字节 `90 78 82 c3 24 40 4c 47` 完全一致（`Data2=0x4024`、`Data3=0x474C`）。**之前把 `474c4024` 读成 `2440-4c47` 是错的**，已修正。

**两个 desc 常量（device slot 73 参数）**：

| VA | 字节 | 说明 |
|---|---|---|
| `0x14615c190` | `00 00 00 00 02 00 00 00 01 00 00 00 00 00 00 00` → 4×u32 `{0,2,1,0}` | 第 1 个命令列表的 desc（`vmovaps xmm0,[...]`） |
| `0x14615c1c0` | `02 02 01 00` → `vpmovsxbd` → `{2,2,1,0}` | 循环里 index 1..10 的 desc |

> **反编译带来的新发现（待办）**：`proxy_slot<73>` 目前**硬编码 `D3D12_COMMAND_LIST_TYPE_DIRECT`**，但静态常量显示第一个 desc 是 `{0,2,1,0}`、后续是 `{2,2,1,0}`。若 desc 第 2 个 u32 是命令列表类型，则第一次应为 `2`（COMPUTE）而非 DIRECT。这不会影响启动断言，但可能影响后续 `Reset` / `ExecuteCommandLists`，**后续调试应从 `a1` 指向的 desc 解析类型，而不是硬编码**。

## 六、反编译出的伪代码（当前启动路径）

### 6.1 命令列表池初始化（函数 `0x142478440..0x142479682` 内）

来源：`cdb_slot73c.log` / `cdb_slot78.log` 反汇编 + 静态常量。

```c
// 全局（.data 零填充区，文件里读不到）
ID3D12Device*               g_device       @ 0x148759d00;
ID3D12GraphicsCommandListX* g_lists[11]    @ 0x1475e7300;
void*                       g_allocs[11]   @ 0x1475e72a0;
static const uint32_t kDescFirst[4] = {0,2,1,0};   // @0x14615c190
static const int32_t  kDescLoop[4]  = {2,2,1,0};   // @0x14615c1c0 (vpmovsxbd)
static const GUID kXboxCmdListIid = {C3827890-4024-474C-98CF-645B51DC4874};
static const GUID kXboxAllocIid  = {6102DEE4-AF59-4B09-B999-B44D73F09B24};

void InitCommandListPool() {
    // ---- 第一个（index 0）----
    Desc d0 = kDescFirst;
    HRESULT hr = g_device->CreateCommandListX(/*slot 73, vtable+0x248*/
                     &d0, g_allocs[0], 0, &kXboxCmdListIid, &g_lists[0]);
    ASSERT_GE_ZERO(hr);                             // int 3 @0x142478b7b
    g_lists[0]->SetBudgetX   (0x700000, 0, 0, 0xFFFFFFFFFF00);  // slot 132 (0x420)
    g_lists[0]->SetBudget2X  (0x00C3C0, 0x80020000, 0, 0xFFFFFFFFFF00); // slot 131 (0x418)
    hr = g_lists[0]->Close();                      // slot 9 (0x48)
    ASSERT_GE_ZERO(hr);                             // int 3 @0x142478bd4

    g_lists[0] 保存进全局数组; g_allocs[0] 保存;

    // ---- index 1..10 ----
    for (int i = 1; i < 11; ++i) {
        if (i <= 4) {
            hr = g_device->CreateCommandAllocator(/*slot 9, vtable+0x48*/
                     2 /*type*/, &kXboxAllocIid, &g_allocs[i]);
            ASSERT_GE_ZERO(hr);                     // int 3 @0x142478c42
        }
        Desc d = kDescLoop;
        hr = g_device->CreateCommandListX(&d, g_allocs[i], 0,
                                          &kXboxCmdListIid, &g_lists[i]);
        ASSERT_GE_ZERO(hr);                         // int 3 @0x142478c7a
        g_lists[i]->SetBudgetX (0x100000, 0, 0, 0xFFFFFFFFFF00);
        g_lists[i]->SetBudget2X(0x00C380, 0x20000, 0, 0xFFFFFFFFFF00);
        hr = g_lists[i]->Close();
        ASSERT_GE_ZERO(hr);
        g_lists[i] / g_allocs[i] 存全局数组;
    }
}
```

**对应到 shim 的修复**：slot 73 映射到 PC `CreateCommandList1`；command-list proxy 的 slot 131/132 返回 S_OK；slot 9（Close）按 Xbox 状态机返回 S_OK（PC 未 Reset 的 list `Close()` 会 `E_FAIL`）。

### 6.2 设备能力 / 显示设置段（同一函数，`0x142478d78` 起）

```c
float fps = ...;                                  // vdivss / vcvttss2si
Settings s = { (uint16_t)(kConst / fps), flag, value, ... };  // @0x1475e0e90
SetupDisplay(&s);                                 // call 0x14247ab10

hr = g_device->SetSomethingX(2, 0, 0, 0);        // device slot 79, [vtable+0x278]
ASSERT_GE_ZERO(hr);                               // int 3 @0x142478dee

if (QueryFeatureX()) {                            // call 0x145c5ff00
    for (int t = 0; t <= 4; ++t)
        g_handleIncrement[t] = g_device->GetDescriptorHandleIncrementSize(t); // slot 15 [vtable+0x78]
    ...
}
```

**对应修复**：Xbox slot 79 是 console-only，PC 同序号是 `CreateSampler2`，把标量 `2` 当 `D3D12_SAMPLER_DESC2*` 会崩在 `CCreateSamplerValidator::Validate` → 直接返回 S_OK。

### 6.3 `appdata0.rpf` 挂载检查（函数 `0x142236e00..0x1422371bd`）

```c
bool EnsureAppDataMounted(Object* o /* rsi */) {
    if (GetFileAttributesW(L"G:\\appdata0.rpf") == INVALID_FILE_ATTRIBUTES) ...  // 之前 error=3
    ...
    if (o->mounted /* [rsi+0xC] */ == 0)
        __debugbreak();                            // RVA 0x2237178 → 12-41 修的 G: 盘符映射
}
```

## 七、Xbox ↔ PC vtable slot 对照（动态实测 + 静态佐证汇总）

| 对象 | Xbox slot | Xbox 语义 | PC 同序号 | 处理 |
|---|---|---|---|---|
| Device | 26 | `GetCustomHeapProperties`（struct return） | 同名 | 交换 `this`/返回缓冲 |
| Device | 48 | `CreateCommandQueue` | `OpenExistingHeapFromAddress` | 映射到 PC slot 8 语义并清洗 Flags/NodeMask |
| Device | 62 | `CreateComputePipelineState` | `CreateStateObject` | 特例 |
| Device | 67 | 从 native code 创建 compute PSO | `CreateProtectedResourceSession1` | 特例 |
| Device | **73** | **`CreateCommandList`** | `CreateShaderCacheSession` | 映射到 PC slot 51 `CreateCommandList1` + 包装 command-list proxy |
| Device | 76 | Xbox 纹理创建 | `CreateCommittedResource3` | 特例 |
| Device | **78** | console-only | 未知（转发未崩） | 观察中 |
| Device | **79** | console-only | **`CreateSampler2`** | 返回 S_OK（否则 AV） |
| CommandList | 9 | `Close`（Xbox 状态机不同） | `Close` | 返回 S_OK，PC list 留给后续 Reset |
| CommandList | **131 / 132** | console-only 预算设置 | **越界**（PC 仅 99 slots） | 返回 S_OK |
| Queue / Fence / Allocator | — | 公共链同序 | 同序 | 项目既有 child proxy |

**PC command list vtable 实测**：`D3D12Core!CCastableCommandList<ID3D12GraphicsCommandList13>`，**99 个方法（0..98）**；slot 99 = `0x400`（数据），`+0x418` = `0x14`，`+0x420` = `0xffffffff` —— 与 13:24 的 AV (`rip=0xffffffff`) 完全吻合。

## 八、结论与对当前调试的价值

1. **静态反编译确认了路径方案正确**：AMD64 原生 + 静态 TLS + 3 个 `d3d12_xs` 导入 + 全部图形走 COM 虚表 → 正解就是"PE 手动映射 + shim + vtable slot 重映射"。
2. **提供了动态调试拿不到的常量**：两个 Xbox IID、两个 desc 常量、`G:\` 在 `.text` 的位置、TLS 回调地址、`.data` 零填充区解释"对象全 0"。
3. **给出函数边界**（`.pdata`）：知道 `0x142478440..0x142479682` 是一个 4.6 KB 的大初始化函数，避免把它误当成多个函数。
4. **发现两个待办**：
   - `proxy_slot<73>` 硬编码 `DIRECT`，应从 `a1` desc 解析类型（静态常量 `{0,2,1,0}` / `{2,2,1,0}`）。
   - Xbox **command allocator IID** `{6102DEE4-...}` 与 PC 不同，`proxy_create_command_allocator` 用 `*riid` 做 `QueryInterface` 存在潜在不兼容（目前启动未卡在此，需观察）。
5. **不替代动态调试**：299,257 个函数、大量运行时构造的状态、GDK 运行时动态解析的 6 个函数指针，全靠 cdb 现场更可靠。后续继续"构建 → 复测 → cdb 抓现场 → 修根因"的自动循环。
