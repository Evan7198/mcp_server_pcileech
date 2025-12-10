# PCILeech MCP 服务器

[English](README.md) | [中文](#中文)

## 中文

一个为 PCILeech 提供标准化接口的模型上下文协议（MCP）服务器，用于基于 DMA 的内存操作。该服务器使 Claude 等 AI 助手能够通过自然语言命令执行内存调试。

**作者：** EVAN & MOER
**支持：** [加入我们的 Discord](https://discord.gg/PwAXYPMkkF)

## 功能特性

- **三个 MCP 工具**：
  - `memory_read`：从任意地址读取内存
  - `memory_write`：向内存写入数据
  - `memory_format`：多视图内存格式化（十六进制转储、ASCII、字节数组、DWORD）

- **低延迟**：直接调用 PCILeech 可执行文件的子进程
- **AI 友好**：通过 MCP 协议提供自然语言接口
- **简单配置**：最小依赖，易于设置
- **多种格式**：以十六进制、ASCII、字节数组和 DWORD 数组查看内存

## 前置要求

- **Windows 10/11**（x64）
- **Python 3.10+**
- **PCILeech 硬件**已正确配置并正常工作
- **PCILeech 可执行文件**（包含在 `pcileech/` 目录中）

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/Evan7198/mcp_server_pcileech
cd mcp_server_pcileech
```

### 2. 安装依赖

创建并激活虚拟环境：

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. 验证 PCILeech

测试 PCILeech 硬件是否正常工作：

```bash
cd pcileech
pcileech.exe probe
```

您应该看到硬件检测输出。

### 4. 配置 Claude Code

将以下配置添加到您的 Claude Code MCP 设置中：

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

**重要提示：** 将 `C:\\path\\to\\mcp_server_pcileech` 替换为您的实际项目路径。

### 5. 重启 Claude Code

添加配置后，重启 Claude Code 以加载 MCP 服务器。

## 配置说明

服务器使用 `config.json` 进行配置：

```json
{
  "pcileech": {
    "executable_path": "pcileech\\pcileech.exe",
    "timeout_seconds": 30
  },
  "server": {
    "name": "mcp-server-pcileech",
    "version": "0.1.0"
  }
}
```

根据您的设置调整 `executable_path` 和 `timeout_seconds`。

## 使用示例

在 Claude Code 中配置完成后，您可以使用自然语言命令：

### 读取内存

```
从地址 0x1000 读取 256 字节
```

### 写入内存

```
将十六进制数据 48656c6c6f 写入地址 0x2000
```

### 格式化内存视图

```
显示地址 0x1000 处 64 字节的格式化视图
```

这将显示：
- 带 ASCII 侧边栏的十六进制转储
- 纯 ASCII 视图
- 字节数组（十进制）
- DWORD 数组（小端序）
- 原始十六进制字符串

## MCP 工具参考

### memory_read

从指定地址读取原始内存。

**参数：**
- `address`（字符串）：十六进制格式的内存地址（例如 "0x1000" 或 "1000"）
- `length`（整数）：要读取的字节数（1-1048576，最大 1MB）

**返回：** 带元数据的内存数据十六进制字符串

### memory_write

向指定地址的内存写入数据。

**参数：**
- `address`（字符串）：十六进制格式的内存地址
- `data`（字符串）：要写入的十六进制数据字符串（例如 "48656c6c6f"）

**返回：** 带确认的成功状态

### memory_format

读取内存并以多种视图格式化以供 AI 分析。

**参数：**
- `address`（字符串）：十六进制格式的内存地址
- `length`（整数）：要读取的字节数（1-4096，最大 4KB）
- `formats`（数组，可选）：要包含的格式类型 - ["hexdump", "ascii", "bytes", "dwords", "raw"]

**返回：** 多格式内存视图

## 架构设计

### 两层设计

1. **MCP 服务器层**（`main.py`）
   - 通过 stdio 传输处理 MCP 协议通信
   - 定义工具架构和参数验证
   - 格式化输出供 AI 分析
   - 异步工具处理器：`handle_memory_read`、`handle_memory_write`、`handle_memory_format`

2. **PCILeech 包装层**（`pcileech_wrapper.py`）
   - 管理 PCILeech 可执行文件的子进程调用
   - 处理地址对齐和分块读取（256 字节块，16 字节对齐）
   - 解析 PCILeech 输出格式
   - 超时和错误处理

### 关键实现细节

**内存读取对齐：**
- PCILeech 的 `display` 命令总是返回对齐到 16 字节边界的 256 字节
- `read_memory()` 自动处理：
  - 计算对齐地址
  - 分块读取 256 字节块
  - 提取和拼接请求的字节范围
  - 支持任意地址和长度

## 故障排除

### PCILeech 未找到

**错误：** `PCILeech executable not found`

**解决方案：** 验证 `config.json` 中的路径指向 `pcileech.exe` 的正确位置

### 硬件未连接

**警告：** `PCILeech connection verification failed`

**解决方案：**
- 确保 PCILeech 硬件正确连接
- 直接使用 `pcileech.exe probe` 测试
- 检查硬件驱动程序是否已安装

### 内存读写失败

**错误：** `Memory read/write failed`

**可能原因：**
- 无效的内存地址
- 硬件访问被拒绝
- 目标系统不可访问
- 权限不足

**解决方案：** 首先使用 PCILeech CLI 测试，验证目标地址有效且可访问。

### 超时错误

**错误：** `PCILeech command timed out`

**解决方案：** 如果操作确实较慢，请在 `config.json` 中增加 `timeout_seconds`。

## 项目结构

```
mcp_server_pcileech/
├── main.py                 # MCP 服务器入口点
├── pcileech_wrapper.py     # PCILeech 集成层
├── config.json             # 配置文件
├── requirements.txt        # Python 依赖
├── pyproject.toml          # 项目元数据
├── README.md               # 英文版
├── README_CN.md            # 本文件（中文版）
├── CLAUDE.md               # Claude Code 指导
├── docs/
│   └── brief.md            # 项目简介
└── pcileech/               # PCILeech 可执行文件和依赖
    └── pcileech.exe
```

## 开发

### 代码格式化

```bash
black main.py pcileech_wrapper.py
```

### 类型检查

```bash
mypy main.py pcileech_wrapper.py
```

### 运行测试

```bash
pytest
```

## 性能

- **MCP 服务器开销：** 每次操作 < 100ms
- **PCILeech 原生性能：** 保持（无额外开销）
- **端到端延迟：** < 5 秒（包括 AI 处理）

## 限制

- **仅限 Windows：** PCILeech 是 Windows 专用
- **硬件依赖：** 需要 PCILeech 硬件连接
- **读取大小限制：**
  - `memory_read`：最大 1MB
  - `memory_format`：最大 4KB（用于可读输出）
- **同步 PCILeech 调用：** 包装器使用 subprocess.run（阻塞），在异步上下文中调用
- **无并发内存操作：** 每个 PCILeech 命令顺序执行

## 安全与法律

**重要免责声明**

此工具设计用于：
- 授权的硬件调试
- 具有适当授权的安全研究
- 教育目的
- 个人硬件开发

**请勿用于：**
- 未经授权访问系统
- 恶意活动
- 未经许可规避安全措施

用户有责任确保其使用符合所有适用的法律法规。

## 许可证

本项目包装了 PCILeech，PCILeech 有其自己的许可证。有关 PCILeech 许可的信息，请参阅 `pcileech/LICENSE.txt`。

## 致谢

- **PCILeech：** [Ulf Frisk](https://github.com/ufrisk/pcileech)
- **模型上下文协议：** [Anthropic](https://modelcontextprotocol.io/)
- **作者：** EVAN & MOER

## 版本

**v0.1.0** - 初始版本

## 支持

- **Discord 社区：** [加入我们的 Discord](https://discord.gg/PwAXYPMkkF)
- **问题反馈：** 在本仓库中提交 issue
- **PCILeech 文档：** [PCILeech GitHub](https://github.com/ufrisk/pcileech)
- **MCP 协议：** [MCP 文档](https://modelcontextprotocol.io/)

## 更新日志

### v0.1.0（2025-12-10）
- 初始版本发布
- 三个 MCP 工具：memory_read、memory_write、memory_format
- PCILeech 子进程集成
- 基本错误处理和超时支持
- Claude Code 集成支持
- 多格式内存可视化
