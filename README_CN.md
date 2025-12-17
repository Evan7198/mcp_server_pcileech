# PCILeech MCP 服务器

[English](README.md) | [中文](#中文)

## 中文

一个为 PCILeech 提供标准化接口的模型上下文协议（MCP）服务器，用于基于 DMA 的内存操作。它可以让 MCP 客户端（例如 Claude Code）通过工具调用完成内存/调试相关工作流。

**作者：** EVAN & MOER  
**支持：** [加入我们的 Discord](https://discord.gg/PwAXYPMkkF)

## 功能特性

- **19 个 MCP 工具**（按能力分组）：
  - **核心内存：** `memory_read`, `memory_write`, `memory_format`
  - **系统：** `system_info`, `memory_probe`, `memory_dump`, `memory_search`, `memory_patch`, `process_list`
  - **地址转换：** `translate_phys2virt`, `translate_virt2phys`, `process_virt2phys`
  - **内核模块（KMD）：** `kmd_load`, `kmd_exit`, `kmd_execute`, `kmd_list_scripts`
  - **高级/FPGA：** `benchmark`, `tlp_send`, `fpga_config`
- **虚拟地址模式：** 内存工具支持 `pid` 或 `process_name`（二选一，互斥）
- **非阻塞服务器：** 通过 `asyncio.to_thread` 执行 PCILeech 调用，避免阻塞事件循环
- **输出辅助：** 支持 hexdump + ASCII + byte/DWORD 视图，便于分析

## 前置要求

- **Windows 10/11**（x64）
- **Python 3.10+**
- **PCILeech 硬件**已正确配置并正常工作
- **PCILeech 二进制文件**（本仓库在 `pcileech/` 下已包含）

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/Evan7198/mcp_server_pcileech
cd mcp_server_pcileech
```

### 2. 安装依赖

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

如果遇到 MCP 相关的导入/版本问题，建议改用 `pyproject.toml` 安装：

```bash
pip install -e .
```

### 3. 验证 PCILeech

```bash
cd pcileech
pcileech.exe probe
```

### 4. 配置 Claude Code（MCP）

在 Claude Code 的 MCP 配置中添加（按实际路径修改）：

```json
"mcpServers": {
  "pcileech": {
    "command": "C:\\path\\to\\mcp_server_pcileech\\.venv\\Scripts\\python.exe",
    "args": [
      "C:\\path\\to\\mcp_server_pcileech\\main.py"
    ],
    "cwd": "C:\\path\\to\\mcp_server_pcileech",
    "env": {}
  }
}
```

修改完成后重启 Claude Code 以加载 MCP 服务器。

## 配置说明

`config.json` 用于指定 PCILeech 可执行文件路径与超时等：

```json
{
  "pcileech": {
    "executable_path": "pcileech\\pcileech.exe",
    "timeout_seconds": 30
  },
  "server": {
    "name": "mcp-server-pcileech",
    "version": "1.0.0"
  }
}
```

## 使用示例

完成配置后，可以直接用自然语言发起请求；客户端会将其转换为工具调用：

```
从地址 0x1000 读取 256 字节
```

```
将十六进制数据 48656c6c6f 写入地址 0x2000
```

```
显示地址 0x1000 处 64 字节的格式化视图
```

## MCP 工具（概览）

说明：
- **虚拟内存模式：** 对内存工具使用 `pid` *或* `process_name`（不可同时使用）。
- **仅 FPGA：** 部分操作需要 FPGA 设备（例如 `memory_probe`、`tlp_send`）。

### 核心内存

- `memory_read(address, length, pid?, process_name?)` → 读取结果（hex + 元数据）
- `memory_write(address, data, pid?, process_name?)` → 写入结果（成功/确认）
- `memory_format(address, length, formats?, pid?, process_name?)` → 多视图（hexdump/ASCII/数组/raw）

### 系统

- `system_info(verbose?)` → 目标系统与设备信息
- `memory_probe(min_address?, max_address?)` → 可读区域（**仅 FPGA**）
- `memory_dump(min_address, max_address, output_file?, force?)` → 转储到文件
- `memory_search(pattern? | signature?, min_address?, max_address?, find_all?)` → 搜索命中
- `memory_patch(signature, min_address?, max_address?, patch_all?)` → 签名修补结果
- `process_list()` → 进程列表（PID/PPID/名称）

### 地址转换

- `translate_phys2virt(physical_address, cr3)` → 地址转换结果
- `translate_virt2phys(virtual_address, cr3)` → 地址转换结果
- `process_virt2phys(pid, virtual_address)` → 地址转换结果

### 内核模块（KMD）

- `kmd_load(kmd_type, use_pt?, cr3?)` → 加载结果（并缓存 KMD 地址）
- `kmd_exit(kmd_address?)` → 卸载结果（省略时使用缓存地址）
- `kmd_execute(script_name, kmd_address?, input_file?, output_file?, parameter_string?, parameter_int0?, parameter_int1?)`
- `kmd_list_scripts(platform?)` → 可用 `.ksh` 脚本（按平台分组）

### 高级 / FPGA

- `benchmark(test_type?, address?)` → 性能结果（与硬件相关）
- `tlp_send(tlp_data?, wait_seconds?, verbose?)` → 发送/接收 TLP（**仅 FPGA**）
- `fpga_config(action?, address?, data?, output_file?)` → 读写配置空间（**仅 FPGA**）

## 架构设计

### 两层设计

1. **MCP 服务器层**（`main.py`）
   - stdio 传输、工具 schema、参数验证、输出格式化
   - 通过 `asyncio.to_thread()` 避免阻塞事件循环
2. **PCILeech 包装层**（`pcileech_wrapper.py`）
   - 以 subprocess 方式调用 `pcileech.exe`
   - 地址对齐与 256 字节分块（匹配 PCILeech `display` 行为）
   - 输出解析、超时与错误映射

## 故障排除

### 找不到 PCILeech

**错误：** `PCILeech executable not found`  
**解决：** 检查 `config.json` → `pcileech.executable_path`

### 硬件未连接

**警告：** `PCILeech connection verification failed`  
**解决：** 先运行 `pcileech\\pcileech.exe probe`，确认驱动/连线/设备正常

### 内存访问失败

**错误：** `Memory read/write failed`  
**解决：** 先用 PCILeech CLI 验证地址/范围可访问，再通过 MCP 重试

### 超时

**错误：** `PCILeech command timed out`  
**解决：** 增大 `config.json` → `pcileech.timeout_seconds`

## 项目结构

```
mcp_server_pcileech/
├── main.py
├── pcileech_wrapper.py
├── config.json
├── pyproject.toml
├── requirements.txt
├── README.md
├── README_CN.md
└── pcileech/
    ├── pcileech.exe
    └── LICENSE.txt
```

## 限制

- 仅限 Windows（本仓库以 Windows 环境为主）
- 实际内存操作依赖兼容的 PCILeech 硬件
- 读取大小限制：
  - `memory_read`：最大 1MB
  - `memory_format`：最大 4KB（可读输出）
- 部分工具为 **仅 FPGA**（probe/TLP/config）
- PCILeech 命令按子进程调用顺序执行（串行）

## 安全与法律

本工具仅用于已授权的调试/安全研究/教育用途。请勿用于未授权访问或恶意行为；使用者需自行确保符合法律法规与授权要求。

## 许可证

本项目封装了 PCILeech，PCILeech 有其自己的许可证。请参阅 `pcileech/LICENSE.txt`。

## 致谢

- **PCILeech：** [Ulf Frisk](https://github.com/ufrisk/pcileech)
- **模型上下文协议：** [Anthropic](https://modelcontextprotocol.io/)
- **作者：** EVAN & MOER

## 版本

本仓库当前包含 19 工具的扩展工具集；具体包/配置版本以以下文件为准：
- `pyproject.toml`（`[project].version`）
- `config.json`（`server.version`）

## 支持

- Discord： [加入我们的 Discord](https://discord.gg/PwAXYPMkkF)
- 问题反馈：在本仓库提交 issue
- PCILeech 文档： [PCILeech GitHub](https://github.com/ufrisk/pcileech)
- MCP 文档： [MCP Documentation](https://modelcontextprotocol.io/)

## 更新日志

### v1.0.0（2025-12-16）
- 扩展到 19 个 MCP 工具，覆盖更完整的 PCILeech 功能
- 内存工具新增虚拟地址模式（`pid` / `process_name`）
- 新增地址转换、KMD、FPGA/高级工具
- 增强参数验证与错误处理；服务器执行保持非阻塞

### v0.1.0（2025-12-10）
- 初始版本
- 三个 MCP 工具：`memory_read`、`memory_write`、`memory_format`
