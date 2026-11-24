# Xbox ↔ PC D3D12 device vtable slot 对照表

Xbox Series 的 `ID3D12Device` 接口在 PC 接口之后**追加了大量 console-only 方法**，并把若干方法换了位置。
PC `ID3D12Device`（本机实现）只有 **83 个 slot**，Xbox 侧至少 **160 个 slot**。

> "按序号转发"只是默认假设。本表由对游戏 EXE 的静态分析 + 运行时实测得出，并与
> [Marvisak/VIctory](https://github.com/Marvisak/VIctory)（`crates/victory-gpu/src/device.rs`）交叉验证。

## 表

| Xbox slot | 偏移 | Xbox 语义 | PC 同序号语义 | 处理方式 |
|---|---|---|---|---|
| 0 | 0x00 | QueryInterface | QueryInterface | 直通 |
| 1 | 0x08 | AddRef | AddRef | 直通 |
| 2 | 0x10 | Release | Release | 直通 |
| 7 | 0x38 | GetNodeCount | GetNodeCount | 直通 |
| 8 | 0x40 | CreateCommandQueue | CreateCommandQueue | 包装为 queue proxy |
| 9 | 0x48 | CreateCommandAllocator | CreateCommandAllocator | PC 侧保持裸对象（宿主 list 无法解包 proxy） |
| 12 | 0x60 | CreateCommandList | CreateCommandList | 直通 |
| 13 | 0x68 | CheckFeatureSupport | CheckFeatureSupport | 直通 |
| 14 | 0x70 | CreateDescriptorHeap | CreateDescriptorHeap | 专用包装 |
| 15 | 0x78 | GetDescriptorHandleIncrementSize | 同 | 直通（注意返回 `UINT`，不是 HRESULT） |
| 16 | 0x80 | CreateRootSignature | 同 | 直通 |
| 17–24 | 0x88–0xC0 | CBV/SRV/UAV/RTV/DSV/Sampler/Copy/CopySimple | 同 | 直通 |
| 25 | 0xC8 | GetResourceAllocationInfo | 同 | 直通 |
| 26 | 0xD0 | GetCustomHeapProperties | 同 | **struct return**：PC 为 `rcx=this, rdx=buf`，Xbox 相反 |
| 27–29 | 0xD8–0xE8 | CreateCommittedResource / CreateHeap / CreatePlacedResource | 同 | 直通 |
| 36 | 0x120 | CreateFence | 同 | 包装为 fence proxy |
| 38 | 0x130 | GetCopyableFootprints | 同 | 直通 |
| 39 | 0x138 | CreateQueryHeap | 同 | 直通 |
| 41 | 0x148 | CreateCommandSignature（**Xbox 变体 IID**） | 同方法，仅接受标准 IID | 转发时替换为 `IID_ID3D12CommandSignature` |
| 48 | 0x180 | CreateCommandQueue（**Xbox 版**） | OpenExistingHeapFromAddress | 映射到 PC slot 8 语义，并清洗 `Flags`/`NodeMask` |
| 61 | 0x1E8 | CreateSamplerX | 同区间不同 | 直通（需核对） |
| 62 | 0x1F0 | CreateComputePipelineStateX | 同区间不同 | 专用包装 |
| 67 | 0x218 | DeserializeComputePipelineStateX | CreateProtectedResourceSession1 | 专用包装 |
| 69 | 0x228 | debug error filter | 同区间不同 | 直通 |
| 70 / 71 | 0x230 / 0x238 | CreatePlacedSRV / CreatePlacedUAV | 同 | 直通 |
| 73 | 0x248 | CreateCommandListX（**Xbox 变体 IID**） | CreateShaderCacheSession | 映射到 PC `CreateCommandList1`（slot 51），并包装为 command-list proxy |
| 74 / 75 | 0x250 / 0x258 | RegisterPagePool / UnregisterPagePool | 同区间不同 | 直通（需核对） |
| 76 | 0x260 | CreateCommittedResourceX | 同区间不同 | 专用包装 |
| **78** | 0x270 | **帧调度：SetInterval** | 同区间不同 | 需按帧调度语义实现 |
| **79** | 0x278 | **帧调度：Schedule** | 同区间不同 | 需按帧调度语义实现（不可转发：PC 同序号是 `CreateSampler2`，会把标量当 desc 指针解引用） |
| **80** | 0x280 | **帧调度：Wait** | 同区间不同 | 需按帧调度语义实现 |
| **81** | 0x288 | **帧调度：Statistics** | 同区间不同 | 需按帧调度语义实现 |
| 86 | 0x2B0 | CreatePipelineStream | 同区间不同 | 直通（需核对） |
| 108 | 0x360 | GetResourceAllocationInfo2 | 同区间不同 | 直通（需核对） |
| 127 | 0x3F8 | CreateCommittedResource3 | 同区间不同 | 直通（需核对） |
| 133 | 0x428 | CreateResourceAtAddress | 同区间不同 | 直通（需核对） |

## 子对象 vtable 长度（实测）

| 对象 | PC 实现的公开方法数 | Xbox 用到的最高 slot |
|---|---|---|
| `ID3D12GraphicsCommandList13` | **99**（slot 0..98；slot 99 起是数据，`vtable+0x420` = `0xffffffff`） | **132** |
| `ID3D12CommandQueue` | 19 | 15 |
| `ID3D12Fence` | 12 | — |
| `ID3D12CommandAllocator` | 9 | — |

裸 PC command list 被按 Xbox vtable 调用时，`call [vtable+0x420]` 会跳到 `0xffffffff` —— 必须代理。

## Xbox 变体 IID 清单

| 名称 | GUID | 说明 |
|---|---|---|
| graphics command list | `C3827890-4024-474C-98CF-645B51DC4874` | PC 无对应；代理直接应答自身 |
| command allocator | `6102DEE4-AF59-4B09-B999-B44D73F09B24` | **就是标准 PC `IID_ID3D12CommandAllocator`**（Xbox 复用），不是变体 |
| command signature | `C36A797C-EC80-4F0A-8985-A7B2475082D1` | PC 只认标准 IID，需替换后转发 |
| command queue | `0EC870A6-5D7E-4C22-8CFC-5BAAE07616ED` | 与 PC 一致 |

> 注意 GUID 的字节序陷阱：内存里 `Data2`/`Data3` 是小端，曾把 `4024-474C` 误读成 `474C-4024` 而长期返回 `E_NOINTERFACE`。
