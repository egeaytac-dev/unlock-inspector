# 🔓 Unlock Inspector

A Windows tool to detect locked files and manage the processes holding them.

## ✨ Features

- 🔍 Detect which processes are locking files
- ⚡ Close or force-kill locking processes
- 🗑️ Smart file deletion with retry logic
- 📋 Detailed logging and export reports

## 📋 Requirements

- Windows 10/11
- Python 3.10+ and PySide6 (for source)
- No requirements for EXE version

## 🚀 Usage

1. Drop a file/folder or click Browse
2. Click Scan to find locked files
3. Use Close, Force, or Delete buttons to manage locks

## 💻 Run from Source

```bash
pip install PySide6
python unlock_inspector.py
```

## 📦 Build EXE

```bash
pip install pyinstaller
pyinstaller --onedir --windowed --icon "icon.ico" unlock_inspector.py
```

## 📄 License

CC BY-NC 4.0 - Personal use only, no commercial use.

Created by **fleur** © 2026
