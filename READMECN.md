# IDAChef

面向 **IDA Pro 9.x** 的 [CyberChef](https://github.com/gchq/CyberChef) 风格数据处理插件。在 IDA 内部即可构建多步骤数据转换链——编码、加解密、压缩、哈希、提取等——并直接针对数据库中的字节或字符串执行，将结果回写为补丁或注释。

```
┌──────────────┬──────────────────┬─────────────────────────────┐
│  Operations  │     Recipe       │         I/O Panel           │
│  (search)    │                  │                             │
│              │  ┌─ From Hex ──┐ │  Input:  5e 73 68 7d 6c...  │
│  Data format │  │  XOR  [0x55]│ │  [Get Selected Bytes]       │
│  ▸ From Hex  │  │  ADD  [3]   │ │  [Get String @ Cursor]      │
│  ▸ To Hex    │  └─────────────┘ │  [From Clipboard]           │
│  ▸ From B64  │                  │                             │
│  ...         │  [Up] [Down]    │  [✓ Auto Bake]  [Bake!]      │
│              │  [Remove][Clear] │                             │
│  Encryption  │                  │  Output:  4b 58 87 7f e8    │
│  ▸ XOR       │  Arguments:      │  [Copy] [Output → Input]    │
│  ▸ AES Dec   │  Key: [0x55   ]  │                             │
│  ...         │                  │  Address: [0x140001000]     │
│              │                  │  [Patch Bytes] [Set Comment]│
└──────────────┴──────────────────┴─────────────────────────────┘
```

## 特性

- **285 个操作**，覆盖 12 大类：编码、密码、压缩、哈希、提取、网络、代码格式化等
- **可停靠的 IDA 面板**（`Ctrl-Alt-C`）——操作浏览器、Recipe 构建器与 I/O 面板集成于同一窗口
- **实时 Auto Bake**——任意参数变更即时重新计算整条 Recipe 链
- **与 IDA 深度集成**——读取选中字节、抓取光标处字符串、将输出结果回写补丁或设置注释
- **公式表达式**——单步内串联多个字节级操作，例如 `FromHex+XOR(0x55)+ADD(3)` 或 `FromBase64+NOT+ROL(3)`
- **自适应参数输入框**——等宽字体输入框随内容自动扩展，并提供实时字节长度提示与 AES 密钥长度识别
- **核心零依赖**——十六进制、Base64/32/85、XOR、gzip/zlib/lzma、SHA 系列、CRC、正则提取等 100+ 操作仅依赖 Python 标准库；AES/DES/RC4 需额外安装 `pycryptodome`（可选）

## 安装

1. 将 `idachef_plugin.py` 与 `idachef/` 目录**一并**复制到 IDA 插件目录：

   | 系统    | 路径                                                        |
   |---------|-------------------------------------------------------------|
   | Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\`                      |
   | macOS   | `~/Library/Application Support/Hex-Rays/IDA Pro/plugins/`  |
   | Linux   | `~/.idapro/plugins/`                                       |

   ```
   plugins/
     idachef_plugin.py
     idachef/
       __init__.py
       core/
         __init__.py
         dish.py
         formula.py
         logger.py
         operation.py
         recipe.py
         utils.py
       operations/
         __init__.py
         arithmetic.py
         ciphers.py
         codeformat.py
         compression.py
         encoding.py
         extractors.py
         hashing.py
         language.py
         networking.py
         other.py
         publickey.py
         textutils.py
       ui/
         __init__.py
         chef_widget.py
         qt_compat.py
   ```

2.（可选）如需 AES/DES/RC4 加解密，请为 IDA 自带的 Python 环境安装 `pycryptodome`：
   ```bash
   "<ida>/python3/python.exe" -m pip install pycryptodome
   ```
   其余功能——Base64/32/85、十六进制、XOR、ROT13/47、gzip/zlib/bzip2/lzma、MD5/SHA*、CRC、HMAC、各类提取器——仅依赖标准库即可使用。

3. 重启 IDA（或通过 **Edit → Plugins → IDAChef** / **Ctrl-Alt-C** 启动）。

## 使用说明

### 打开插件
**Edit → Plugins → IDAChef**，或按下 **Ctrl-Alt-C**。

### 三栏式布局

- **左侧 —— 操作浏览器**：可搜索、按类别组织的操作树。双击某项即可添加到 Recipe；在搜索框中输入关键字可按名称、类别或描述进行过滤。

- **中间 —— Recipe**：当前操作链的有序列表。点击某一步可编辑其参数；通过 **Up** / **Down** / **Remove** / **Clear** 按钮调整顺序或清空。启用 **Auto Bake** 后，参数变更会实时生效。

- **右侧 —— I/O 面板**：
  - **输入**：可直接粘贴文本，或从 IDA 中获取数据：
    - **Get Selected Bytes** —— 读取当前 Hex View / 反汇编视图中选中的内容，并以十六进制字符串形式展示
    - **Get String @ Cursor** —— 读取光标所在位置的字符串字面量
    - **From Clipboard** —— 粘贴剪贴板内容
  - **输出**：以所选格式展示最终结果（Auto 十六进制/文本、Hex、UTF-8、Latin-1、Base64、十进制字节）
  - **操作按钮**：
    - **Copy Output** —— 将结果复制到剪贴板
    - **Output → Input** —— 将结果作为新的输入回填
    - **Patch Bytes at Address** —— 将输出字节写入 IDA 数据库中指定地址
    - **Set Comment at Address** —— 将输出文本设置为指定地址处的注释

### 输入解析规则

输入文本默认按**纯文本**处理（支持 `\xHH` 转义）。若需要对输入先行解码，请在 Recipe 中显式添加 `From Hex`、`From Base64`、`From Binary` 等步骤。

### IDA 输出窗口日志

每次执行 Bake 时，会在 IDA 输出窗口打印三类信息：

```
Input: 5e6877497d7d71526c776d536c707c6c
Step 1 'From Hex' -> ^hwI}}qRlwmSlp|l
Step 2 'XOR' -> KX...
Result: KX...
```

- **Input**：原始输入文本（或从 IDA 读取并解码后的字节串）
- **Step N 'Operation'**：Recipe 中每一步执行**后**的输出
- **Result**：最终输出结果

所有字节内容均以解码文本形式打印（优先 UTF-8，回退 Latin-1），超过 300 字符将被截断；出错时会附带对应步骤序号及异常信息。

## 公式表达式

**Formula（复合）**操作允许在单个 Recipe 步骤中，通过表达式语法串联多个字节级操作：

```
FromHex+XOR(0x55)+ADD(3)      — 解码十六进制，与 0x55 异或，再加 3（模 256）
FromBase64+NOT+ROL(3)         — 解码 Base64，按位取反，循环左移 3 位
XOR(0xaa)+SHR(2)+AND(0x7f)   — 依次执行异或、右移、掩码
```

**支持的字节级操作**：`XOR`、`ADD`、`SUB`、`AND`、`OR`、`NOT`、`ROL`、`ROR`、`SHL`、`SHR`、`MUL`、`MOD`

**可选的 `From` 前缀**：`FromHex` 或 `FromBase64`（在执行字节级操作前，先对整个输入进行解码）。若未指定前缀，则直接使用原始输入字节。

`XOR`/`ADD`/`SUB`/`AND`/`OR`/`MUL`/`MOD` 中的密钥可以是十六进制（`0xNN`）或十进制整数；多字节十六进制密钥将被循环重复使用。

## 操作分类一览（共 285 项）

### 数据格式（50）
Hex、Hexdump、Base64、Base32、Base45、Base85、Base58、Base62、Binary、Octal、Decimal、Float、Charcode 的编解码；URL 编解码、HTML 实体、摩斯电码、Quoted-Printable；字节序转换、字符串/Unicode 转义与反转义、Punycode、BCD、Hex Content；CSV↔JSON、Unicode 规范化、文本↔整数转换、生成 UUID。

### 加密 / 编码（50）
XOR、XOR 暴力破解（含评分与已知明文匹配）、ROT13/暴力破解、ROT47/暴力破解、ROT8000、ROR13、Atbash、维吉尼亚密码编解码、位移左/右；RC4/RC4 Drop；AES 加解密（CBC/ECB/CTR/GCM）、AES 密钥包装/解包；DES/3DES 加解密；Blowfish 加解密；RC2 加解密；ChaCha20；TEA/XTEA/XXTEA 加解密；替换密码、Affine/A1Z26/栅栏/培根/Bifid 密码编解码、凯撒盒；PBKDF2/HKDF 密钥派生；Bcrypt、Scrypt。

### 压缩（19）
Gzip/Gunzip、Zlib 压缩/解压、Raw Deflate/Inflate、Bzip2 压缩/解压、LZMA 压缩/解压；Tar/Untar、Zip/Unzip；LZ4 压缩/解压、LZString 压缩/解压、LZNT1 解压。

### 哈希（33）
MD2、MD4、MD5、SHA0、SHA1、SHA224、SHA256、SHA384、SHA512、SHA2（统一接口）、SHA3-224/256/384/512、SHA3（统一接口）、Keccak、RIPEMD160、BLAKE2b、BLAKE2s；CRC16（CCITT/IBM）、CRC32、CRC-8/16/32（统一接口）、Adler32、Fletcher 校验、TCP/IP 校验和、XOR 校验和、Luhn 校验、奇偶校验位；HMAC、CMAC、MurmurHash3、NT Hash、LM Hash；信息熵、频率分布、哈希类型分析。

### 工具（35）
反转、大小写转换（大写/小写/交换/交替/自定义）；去除空白/空字节/ANSI 转义码/行号/变音符号；查找替换（正则）、正则表达式、排序、乱序、去重、拆分、过滤；Head、Tail、字节截取/丢弃、行填充、添加行号、计数出现次数；文本对比（Diff）、汉明/编辑距离；UNIX 时间戳↔日期转换、解析日期时间、获取当前时间；JWT 解码；重合指数、卡方检验。

### 提取器（13）
提取 IPv4/IPv6、URL、邮箱、域名、十六进制字符串、MAC 地址、哈希值、文件路径、日期；自定义正则（列表 + 计数）、字符串提取（ASCII + UTF-16LE）、RAKE 关键词提取。

### 网络（17）
IP/URL 的 Defang/Refang；MAC 地址格式化（含/不含 `:` 或 `-`）；解析 IPv6、IPv6 展开/压缩；CIDR↔IP 范围互转；IPv4↔十进制互转；解析 URI、URL 编解码。

### 代码整理（14）
JSON 美化/压缩、XML 美化/压缩、SQL 美化/压缩、CSS 美化/压缩、JavaScript 美化/压缩、去除 HTML 标签、通用代码美化、PHP 序列化/反序列化。

### 算术 / 逻辑（24）
求和、求差、求积、求商、均值、中位数、标准差；扩展欧几里得算法、模逆元；集合并集/交集/差集/对称差集；按位 AND/OR/NOT、加/减（模 256）、取模；位移左/右、循环左移/右移。**Formula（复合）**——支持 FromHex/FromBase64 前缀的字节级操作链。

### 语言（7）
NATO 音标字母互转、Leet Speak 转换、文本编解码、Unicode 文本格式化、智能字符转义。

### 其他（10）
伪随机数/素数生成器、De Bruijn 序列、循环模式生成器、重合指数、卡方检验、x86 反汇编（基于 capstone）、生成 Lorem Ipsum、Haversine 距离、HTML 转文本。

### 公钥密码学（13）
RSA 加解密/签名/验签、生成 RSA 密钥对、从证书/私钥提取公钥；解析 X.509、ASN.1 十六进制转储、PEM↔Hex 互转；PGP 加解密/验签。

## 参数输入界面

- **文本/数字输入框**采用 `AutoGrowLineEdit` 组件——等宽字体，随内容自动扩展（最大 520px），确保 64 字符的十六进制密钥或较长的 XOR 字符串完整可见
- **Key/IV/Nonce/Salt 字段**提供实时提示，例如 `"32 chars → 16 bytes as Hex (AES-128 / DES3-ok)"`；当字节数匹配已知密钥长度时会以绿色高亮显示
- **短选项列表**（≤ 6 个选项，例如 CBC/ECB/CTR/GCM）以**单选按钮**而非下拉框呈现，当前选择与所有备选项一目了然

## 扩展开发

通过继承 `idachef.core.operation.Operation` 即可添加新操作：

```python
from ..core.operation import Operation

class MyOp(Operation):
    name = "My Operation"
    category = "Utils"
    description = "Does something useful."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "Fast",
         "options": ["Fast", "Slow"]},
    ]

    def _run(self, data, args):
        key = self.get_arg(args, "Key", "")
        # ... 执行数据转换 ...
        return result
```

将新操作加入对应 `idachef/operations/*.py` 文件中的 `OPERATIONS` 列表（或新建文件并在 `__init__.py` 中注册），即可自动出现在操作浏览器中，无需编写任何 UI 代码。

## 架构

```
idachef/
├── core/                 # 处理管线核心
│   ├── operation.py      #   Operation 基类
│   ├── recipe.py         #   Recipe 链式执行器 + BakeResult
│   ├── dish.py           #   bytes ↔ str 转换辅助工具
│   ├── formula.py        #   复合公式解析器（FromHex+XOR+ADD…）
│   ├── utils.py          #   通用工具函数（key_bytes、bytewise_op 等）
│   └── logger.py         #   IDA 输出窗口 / 回退日志记录器
├── operations/           # 285 个操作类，按 12 个类别模块组织
│   └── __init__.py       #   操作注册表 + 搜索
├── ui/
│   ├── chef_widget.py    #   主停靠窗口（操作浏览器、Recipe 面板、I/O 面板）
│   └── qt_compat.py      #   PyQt5 ↔ PySide6 兼容层
└── __init__.py
```

整体架构参照 CyberChef 的 `Operation.mjs` → `Recipe.mjs` → `Dish.mjs` 处理管线：每个操作的输出即为下一步的输入；任一步骤失败时，Bake 过程终止并同时返回已产生的部分输出与错误信息。

## 测试

共 157 个自动化测试，覆盖编码、哈希、密码学、算术、工具类操作以及公式表达式：

```bash
cd /path/to/IDAChef
python tests/run_all.py
```

## 兼容性

- **IDA Pro 9.0**（PyQt5）与 **9.2+**（PySide6）—— `qt_compat.py` 自动适配两者
- **Python 3.8+**

## 免责声明

本项目为参考 CyberChef 设计思路与操作集合、从零重新实现的 Python 版本，未包含或复用任何 CyberChef 源代码。CyberChef © UK Crown Copyright / GCHQ，遵循 Apache-2.0 协议开源，详见 https://github.com/gchq/CyberChef。