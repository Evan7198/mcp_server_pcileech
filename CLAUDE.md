# CLAUDE.md

此文件为 Claude Code (claude.ai/code) 在此代码库中工作时提供指导。

## 项目概述

这是一个 MCP (Model Context Protocol) 服务器,为 PCILeech 提供标准化接口,实现基于 DMA 的内存读写操作。它允许 AI 助手通过自然语言命令执行内存调试操作。

**关键特性:**
- 通过 stdio 运行的 MCP 服务器
- 包装 PCILeech 可执行文件进行 DMA 内存操作
- 提供三个 MCP 工具:memory_read、memory_write、memory_format
- 异步架构使用 Python asyncio

## 核心架构

### 两层设计

1. **MCP 服务器层** (`main.py`)
   - 处理 MCP 协议通信 (stdio transport)
   - 定义工具架构和参数验证
   - 格式化输出供 AI 分析 (hexdump、ASCII、字节数组、DWORD 数组)
   - 异步工具处理器:`handle_memory_read`、`handle_memory_write`、`handle_memory_format`

2. **PCILeech 包装层** (`pcileech_wrapper.py`)
   - 管理 PCILeech 可执行文件的 subprocess 调用
   - 处理地址对齐和分块读取 (display 命令返回 256 字节,对齐到 16 字节边界)
   - 解析 PCILeech 输出格式
   - 超时和错误处理

### 关键实现细节

**内存读取对齐:**
- PCILeech 的 `display` 命令总是返回 256 字节,对齐到 16 字节边界
- `read_memory()` 自动处理:
  - 计算对齐地址
  - 分块读取 256 字节块
  - 提取和拼接请求的字节范围
  - 支持任意地址和长度

**配置系统:**
- `config.json` 定义可执行文件路径和超时
- 路径相对于配置文件解析为绝对路径
- 懒加载初始化 - 不在启动时验证硬件连接

## 常用命令

### 开发环境设置

```bash
# 激活虚拟环境
.venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt
```

### 运行服务器

```bash

# 通过 Claude Code 集成运行 (推荐)
# 在 Claude Code 的 MCP 服务器配置中添加:
```

```json
{
  "args": [
    "C:\\Users\\Administrator\\Desktop\\mcp_server_pcileech\\main.py"
  ],
  "command": "C:\\Users\\Administrator\\Desktop\\mcp_server_pcileech\\.venv\\Scripts\\python.exe",
  "cwd": "C:\\Users\\Administrator\\Desktop\\mcp_server_pcileech",
  "env": {}
}
```

**配置说明:**
- `command`: 必须使用虚拟环境中的 Python 可执行文件路径
- `args`: 指向 main.py 的绝对路径
- `cwd`: 项目根目录,确保能找到 config.json 和 pcileech 目录
- `env`: 可选的环境变量 (通常为空)

### 开发工具

```bash
# 代码格式化
black main.py pcileech_wrapper.py

# 类型检查
mypy main.py pcileech_wrapper.py

# 测试 (如果有)
pytest
```

### PCILeech 验证

```bash
# 验证 PCILeech 硬件
cd pcileech
pcileech.exe probe

# 测试内存读取
pcileech.exe display -min 0x1000
```

## 修改代码时的注意事项

### 添加新的 MCP 工具
1. 在 `list_tools()` 中定义工具架构
2. 在 `call_tool()` 中添加工具路由
3. 实现异步处理器函数 `async def handle_<tool_name>(args: dict) -> list[TextContent]`
4. 使用 `get_pcileech()` 访问 PCILeech 包装器

### 修改内存操作
- 所有内存地址处理都在 `pcileech_wrapper.py` 中
- 记住 `display` 命令的 256 字节/16 字节对齐限制
- 解析逻辑在 `_parse_display_output()` 中 - 处理偏移、十六进制和 ASCII 列
- 始终规范化地址 (移除 '0x' 前缀进行内部处理)

### 错误处理
- 使用 `PCILeechError` 用于所有 PCILeech 相关错误
- MCP 工具处理器捕获异常并返回 TextContent 错误
- 超时在 `config.json` 中配置,在包装器中强制执行

### 输出格式
- `memory_format` 工具提供多种视图供 AI 分析
- 格式化函数:`format_memory_dump()`、`format_ascii_view()`、`format_byte_array()`、`format_dword_array()`
- 保持输出清晰和可解析 - AI 将处理它

## 重要限制

- **仅 Windows**: PCILeech 是 Windows 专用
- **硬件依赖**: 需要 PCILeech 硬件连接
- **读取大小限制**:
  - `memory_read`: 最大 1MB
  - `memory_format`: 最大 4KB (用于可读输出)
- **同步 PCILeech 调用**: 包装器使用 subprocess.run (阻塞),但在异步上下文中调用
- **无并发内存操作**: 每个 PCILeech 命令都是顺序执行的

## 调试技巧

1. **检查 PCILeech 输出**: 包装器记录命令和原始输出 (INFO 级别)
2. **验证地址对齐**: 使用 `pcileech.exe display -min <addr>` 直接测试
3. **解析问题**: 检查 `_parse_display_output()` 正则表达式和行格式
4. **MCP 协议**: 服务器在 stdio 上运行 - 确保没有打印语句干扰协议
5. **超时**: 如果操作合理地慢,在 `config.json` 中增加 `timeout_seconds`

## 安全上下文

此工具设计用于:
- 授权的硬件调试
- 安全研究 (具有适当授权)
- 教育目的
- 个人硬件开发

不要用于未经授权的访问或恶意活动。用户负责遵守所有适用法律。
