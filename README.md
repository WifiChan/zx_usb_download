# ZX297520V3 USB Download Tool

[`zx_usb_download.py`](zx_usb_download.py) 是面向 **中兴微电子 (Sanechip) ZX297520V3** 平台的 **两阶段 USB RAM 下载引导工具**，参考并修改自 **`zx297520v3-loader-main`（Rust / `nusb`）**，使用 Python 重新实现，增强了Windows端支持，用于在无 Flash 固件或救砖场景下通过 USB 将 `tloader` / `openloader` 与 `u-boot.bin` 加载至内存运行。

---

## 核心特性

1. **两阶段 RAM 引导协议**
   - **Stage 1（BootROM → SRAM `0x00082000`）**：与 BootROM 执行 `0x5A / 0xA5` 握手，按 8KB 分片下载 `tloader` / `openloader` 并跳转初始化 DRAM。若输入的 Stage 1 裸二进制缺少 `0x1B8`（440 字节、`ZX7521V1` 魔数）引导头，脚本会自动补全默认引导头。
   - **Stage 2（Openloader → DDR `0x21DF0000`）**：复用 Stage 1 已建立的 USB 通道（无需重新枚举），与 Openloader 握手后按 128KB（串口模式下自动限制为 8KB）分片下载 `u-boot.bin` 并跳转执行。
2. **安全启动绕过（CVE-2026-40003）**
   - 支持 `-e` / `--exploit` 参数启用 Joselito 漏洞利用，向 SRAM `0x81FD0` 写入入口跳转地址，绕过 BootROM 安全启动校验。
3. **双传输模式与智能端口识别**
   - **USB Bulk 模式（`pyusb`）**：直接操作 USB Bulk 端点（`EP IN 0x81` / `EP OUT 0x01`，`VID 0x19D2` / `PID 0x0256`）。Windows需要安装libusb驱动。
   - **Serial CDC 模式（`pyserial`，推荐 Windows 使用）**：通过 `--serial` 强制使用串口模式（不强制也会在识别到DL1时使用，无需将驱动替换为 libusb，可保留原厂串口与后续 U-Boot 的 **USB RNDIS 网卡**驱动），未指定 `-p` 时会自动识别 ZTE `DL1` / `MI_00` 下载口，并自动过滤常见调试串口（CH34x / CP210x / FTDI）和 `DL2`（`MI_01`）。Windows需要安装ZXIC原厂端口驱动。
4. **兼容原厂 `tboot`**
   - 支持 `-s` / `--stock` 参数适配原厂 `tboot` 的额外 `0x5A / 0xA7` 同步握手（配合 `--ddr 0x27EF0000`）。

---

## 环境依赖

- **Python 3**
- 安装依赖库：
  ```bash
  pip install pyserial pyusb
  ```
  - 仅使用 `--serial` 串口模式时，只需安装 `pyserial` 和中兴 USB 下载串口驱动。
  - 使用 USB Bulk 模式时，需要 `pyusb` 以及系统 `libusb` 后端（Windows 下需配合 WinUSB / libusbK 驱动）。

---

## 命令行参数

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `-p`, `--port` | 自动识别 `DL1` | 指定串口号（如 `COM97` 或 `/dev/ttyUSB0`） |
| `-1`, `--stage1` | `./tloader.bin` | Stage 1 镜像路径（`tloader` / `openloader`） |
| `-2`, `--stage2` | `./u-boot.bin` | Stage 2 镜像路径（主线 `u-boot.bin` 或原厂 `tboot`） |
| `--sram` | `0x00082000` | Stage 1 SRAM 加载地址 |
| `--ddr` | `0x21DF0000` | Stage 2 DDR 加载地址（原厂 `tboot` 为 `0x27EF0000`） |
| `-e`, `--exploit` | 关闭 | 启用安全启动绕过（CVE-2026-40003） |
| `-s`, `--stock` | 关闭 | 原厂 `tboot` 模式（Stage 2 跳转后执行额外 `0x5A/0xA7` 同步） |
| `--serial` | 关闭 | 强制使用 Serial CDC 模式（跳过 USB Bulk 探测） |

---

## 使用示例

将目标 `tloader.bin`（或 `openloader.bin`）与未压缩的 `u-boot.bin` 放在当前目录（或通过 `-1` / `-2` 指定路径），然后运行脚本，再将设备上电进入 USB 下载模式（`19D2:0256`）：

1. **串口模式（自动识别 `DL1`，推荐 Windows 使用）**：
   
   ```bash
   python zx_usb_download.py -e --serial
   ```
2. **手动指定串口号与镜像文件**：
   ```bash
   python zx_usb_download.py -e --serial -p COM97 -1 ./openloader.bin -2 ./u-boot.bin
   ```
3. **[CVE-2026-40003](https://github.com/rva3/CVE-2026-40003) 注入模式**：
   
   ```bash
   python zx_usb_download.py -e
   ```

加载成功后，配套的 [Web Failsafe U-Boot](https://github.com/WifiChan/7520v3-u-boot)会自动通过 USB RNDIS 启动，在浏览器访问 **`http://192.168.72.1/`** 即可进行救砖与刷机操作。

---

## 致谢

参考项目：`zx297520v3-loader-main`（Rust / `nusb` 实现）

感谢Google Antigravity提供的Gemini 3.8 Flash与Gemini 4 Argon帮我实现了这个离谱的创意。

感谢[铸币](https://space.bilibili.com/35981144)与[小风时雨](https://github.com/yueluoying)两位朋友的测试与问题反馈。

以及感谢所有认真看完README并使用的各位用户......
