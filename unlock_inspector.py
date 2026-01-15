#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unlock Inspector - File Lock Detection & Process Management Tool

Detects locked files using Windows Restart Manager API and provides
options to close processes or delete locked files safely.

Copyright (c) 2026 fleur
All rights reserved.

This software is licensed under the Creative Commons
Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0).

You are free to:
  - Share: copy and redistribute the material
  - Adapt: remix, transform, and build upon the material

Under the following terms:
  - Attribution: You must give appropriate credit
  - NonCommercial: You may not use the material for commercial purposes

Full license: https://creativecommons.org/licenses/by-nc/4.0/

Version: 1.0.0
Platform: Windows 10/11
Requirements: Python 3.10+, PySide6
"""

import os
import sys
import ctypes
import time
import stat
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from enum import Enum

# High DPI support - must be set before QApplication
os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
os.environ["QT_SCALE_FACTOR_ROUNDING_POLICY"] = "PassThrough"

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QScrollArea, QFrame, QProgressBar,
    QFileDialog, QTabWidget, QTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSize
from PySide6.QtGui import QFont, QTextCursor, QIcon, QPainter
from PySide6.QtSvg import QSvgRenderer


# ============== SVG Icon Helper ==============

INFO_ICON_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="10"/>
  <line x1="12" y1="16" x2="12" y2="12"/>
  <line x1="12" y1="8" x2="12.01" y2="8"/>
</svg>'''

def create_svg_icon(svg_data: str, color: str, size: int = 18) -> QIcon:
    from PySide6.QtGui import QPixmap
    svg_colored = svg_data.format(color=color)
    renderer = QSvgRenderer(svg_colored.encode())
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


# ============== Theme ==============

class Colors:
    BG = "#1a1a1a"
    BG_CARD = "#242424"
    BG_INPUT = "#2a2a2a"
    BORDER = "#3a3a3a"
    TEXT = "#e0e0e0"
    TEXT_DIM = "#808080"
    
    # Purple theme
    ACCENT = "#9b7bcf"
    ACCENT_SOFT = "#7c5db5"
    
    # Status colors
    DANGER = "#cf6679"
    SUCCESS = "#81c784"
    WARNING = "#ffb74d"


# ============== Button Styles ==============

# Button dimensions
BTN_WIDTH = 70
BTN_HEIGHT = 28

def get_btn_style(color: str) -> str:
    return f"""
        QPushButton {{
            background-color: transparent;
            color: {color};
            font-size: 11px;
            font-weight: bold;
            padding: 4px 8px;
            border: 1px solid {color};
            border-radius: 4px;
            min-width: {BTN_WIDTH}px;
            max-height: {BTN_HEIGHT}px;
        }}
        QPushButton:hover {{
            background-color: rgba(155, 123, 207, 0.15);
        }}
        QPushButton:disabled {{
            color: #555555;
            border-color: #555555;
        }}
    """

BTN_PRIMARY = get_btn_style(Colors.ACCENT)
BTN_DANGER = get_btn_style(Colors.DANGER)
BTN_DEFAULT = get_btn_style(Colors.TEXT_DIM)


# Modal overlay for confirmations

class ModalOverlay(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setGeometry(parent.rect())
        self._callback = None
        self._bg = QWidget(self)
        self._bg.setGeometry(self.rect())
        self._bg.setStyleSheet("background-color: rgba(0, 0, 0, 0.6);")
    
    def show_confirm(self, title: str, message: str, danger: bool, callback):
        self._callback = callback
        self.show()
        self.raise_()
        
        border_color = Colors.DANGER if danger else Colors.ACCENT
        
        dialog = QFrame(self)
        dialog.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.BG_CARD};
                border: 2px solid {border_color};
                border-radius: 8px;
            }}
        """)
        dialog.setFixedSize(320, 140)
        dialog.move((self.width() - 320) // 2, (self.height() - 140) // 2)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)
        
        # Title - no border, transparent background
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {Colors.TEXT}; font-size: 15px; font-weight: bold; border: none; background: transparent;")
        layout.addWidget(title_lbl)
        
        # Message - no border, transparent background, larger text
        msg_lbl = QLabel(message)
        msg_lbl.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 13px; border: none; background: transparent;")
        msg_lbl.setWordWrap(True)
        layout.addWidget(msg_lbl)
        
        layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        btn_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(BTN_DEFAULT)
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(lambda: self._respond(False))
        btn_layout.addWidget(cancel_btn)
        
        confirm_btn = QPushButton("Confirm")
        confirm_btn.setStyleSheet(BTN_DANGER if danger else BTN_PRIMARY)
        confirm_btn.setCursor(Qt.PointingHandCursor)
        confirm_btn.clicked.connect(lambda: self._respond(True))
        btn_layout.addWidget(confirm_btn)
        
        layout.addLayout(btn_layout)
        
        dialog.show()
    
    def _respond(self, result: bool):
        if self._callback:
            self._callback(result)
        self.deleteLater()


# ============== Windows Restart Manager API ==============

class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]

class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * 256),
        ("strServiceShortName", wintypes.WCHAR * 64),
        ("ApplicationType", wintypes.DWORD),
        ("AppStatus", wintypes.DWORD),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]

rstrtmgr = ctypes.windll.rstrtmgr
kernel32 = ctypes.windll.kernel32
ERROR_MORE_DATA = 234


# ============== Data Models ==============

@dataclass
class LockingProcess:
    pid: int
    name: str
    app_type: int
    
    @property
    def type_name(self) -> str:
        return {0: "Unknown", 1: "App", 2: "App", 3: "Service", 4: "Explorer", 5: "Console", 1000: "Critical"}.get(self.app_type, "Unknown")

@dataclass  
class LockedFile:
    path: str
    processes: List[LockingProcess]
    
    @property
    def filename(self) -> str:
        return os.path.basename(self.path)


# ============== Restart Manager Service ==============

def get_locking_processes(filepath: str) -> List[LockingProcess]:
    processes = []
    if not os.path.exists(filepath):
        return processes
    
    filepath = os.path.abspath(filepath)
    session_handle = wintypes.DWORD()
    session_key = ctypes.create_unicode_buffer(64)
    
    if rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key) != 0:
        return processes
    
    try:
        files_array = (wintypes.LPCWSTR * 1)(ctypes.c_wchar_p(filepath))
        if rstrtmgr.RmRegisterResources(session_handle.value, 1, files_array, 0, None, 0, None) != 0:
            return processes
        
        proc_info_needed = wintypes.UINT(0)
        proc_info = wintypes.UINT(0)
        reboot_reasons = wintypes.DWORD(0)
        
        result = rstrtmgr.RmGetList(session_handle.value, ctypes.byref(proc_info_needed),
                                     ctypes.byref(proc_info), None, ctypes.byref(reboot_reasons))
        
        if result == ERROR_MORE_DATA and proc_info_needed.value > 0:
            proc_info_array = (RM_PROCESS_INFO * proc_info_needed.value)()
            proc_info.value = proc_info_needed.value
            
            if rstrtmgr.RmGetList(session_handle.value, ctypes.byref(proc_info_needed),
                                   ctypes.byref(proc_info), proc_info_array, ctypes.byref(reboot_reasons)) == 0:
                for i in range(proc_info.value):
                    info = proc_info_array[i]
                    processes.append(LockingProcess(pid=info.Process.dwProcessId, name=info.strAppName, app_type=info.ApplicationType))
    finally:
        rstrtmgr.RmEndSession(session_handle.value)
    
    return processes


def kill_process(pid: int, force: bool = False) -> tuple[bool, str]:
    try:
        if force:
            handle = kernel32.OpenProcess(0x0001, False, pid)
            if handle:
                result = kernel32.TerminateProcess(handle, 1)
                kernel32.CloseHandle(handle)
                return (True, "Terminated") if result else (False, "Failed")
            return False, "Access denied"
        else:
            os.kill(pid, 9)
            return True, "Closed"
    except PermissionError:
        return False, "Access denied"
    except ProcessLookupError:
        return True, "Already ended"
    except Exception as e:
        return False, str(e)


# ============== Action Results ==============

class ActionResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    RETRY_NEEDED = "retry"


@dataclass
class DeleteAttempt:
    attempt_num: int
    strategy: str
    success: bool
    error: Optional[str] = None
    

@dataclass
class DeleteResult:
    success: bool
    file_path: str
    attempts: List[DeleteAttempt] = field(default_factory=list)
    final_error: Optional[str] = None
    file_still_exists: bool = True
    processes_killed: List[str] = field(default_factory=list)


# ============== Smart File Deleter ==============

class SmartFileDeleter:
    """
    Smart file deletion with retry logic and fallback strategies.
    Based on professional tools like LockHunter and UnLock IT.
    
    Deletion failure reasons:
    - File in use (process holding handle)
    - Read-only attribute
    - Permission denied (ACL issues)
    - System protected file
    - Process respawning after kill
    - Anti-malware blocking
    - NTFS file system corruption
    """
    
    MAX_ATTEMPTS = 3
    RETRY_DELAY = 0.5  # seconds
    PROCESS_KILL_WAIT = 0.3  # wait after killing process
    
    def __init__(self, log_callback: Optional[Callable] = None):
        self.log_callback = log_callback
    
    def _log(self, message: str, level: str = "info"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def delete_file(self, filepath: str, kill_processes: bool = True) -> DeleteResult:
        """Attempt to delete a file using multiple strategies."""
        result = DeleteResult(success=False, file_path=filepath)
        
        # Check if file exists
        if not os.path.exists(filepath):
            result.success = True
            result.file_still_exists = False
            result.attempts.append(DeleteAttempt(0, "check_exists", True))
            self._log("File does not exist - nothing to delete", "info")
            return result
        
        # Strategy 1: Kill locking processes first
        if kill_processes:
            self._log("Checking for locking processes...", "info")
            processes = get_locking_processes(filepath)
            
            if processes:
                self._log(f"Found {len(processes)} locking process(es)", "warn")
                for proc in processes:
                    # Try graceful close first, then force kill
                    ok, msg = kill_process(proc.pid, force=False)
                    if not ok:
                        ok, msg = kill_process(proc.pid, force=True)
                    
                    if ok:
                        result.processes_killed.append(f"{proc.name} (PID: {proc.pid})")
                        self._log(f"Killed: {proc.name} (PID: {proc.pid})", "success")
                    else:
                        self._log(f"Failed to kill {proc.name}: {msg}", "warn")
                
                # Wait for handles to be released
                time.sleep(self.PROCESS_KILL_WAIT)
                
                # Check if processes respawned
                new_procs = get_locking_processes(filepath)
                if new_procs:
                    self._log(f"Warning: {len(new_procs)} process(es) respawned", "warn")
                    for proc in new_procs:
                        kill_process(proc.pid, force=True)
                    time.sleep(self.PROCESS_KILL_WAIT)
            else:
                self._log("No locking processes found", "info")
        
        # Define deletion strategies (order matters)
        strategies = [
            ("direct_delete", self._try_direct_delete),
            ("remove_readonly", self._try_remove_readonly),
            ("fix_permissions", self._try_with_permission_fix),
            ("force_delete_api", self._try_force_delete),
            ("rename_and_delete", self._try_rename_delete),
        ]
        
        # Try each strategy with retries
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            self._log(f"=== Deletion Attempt {attempt}/{self.MAX_ATTEMPTS} ===", "info")
            
            for strategy_name, strategy_func in strategies:
                try:
                    success, error = strategy_func(filepath)
                    result.attempts.append(DeleteAttempt(attempt, strategy_name, success, error))
                    
                    if success:
                        # Verify file is actually deleted
                        time.sleep(0.1)
                        if not os.path.exists(filepath):
                            result.success = True
                            result.file_still_exists = False
                            self._log(f"Success with strategy: {strategy_name}", "success")
                            return result
                        else:
                            self._log(f"{strategy_name}: reported success but file still exists", "warn")
                    else:
                        if error:
                            self._log(f"{strategy_name}: {error}", "debug")
                            
                except Exception as e:
                    error_msg = str(e)
                    result.attempts.append(DeleteAttempt(attempt, strategy_name, False, error_msg))
                    self._log(f"{strategy_name} exception: {error_msg}", "error")
            
            # Wait before next attempt
            if attempt < self.MAX_ATTEMPTS:
                self._log(f"Waiting {self.RETRY_DELAY}s before next attempt...", "info")
                time.sleep(self.RETRY_DELAY)
                
                # Re-check for new locking processes
                if kill_processes:
                    new_procs = get_locking_processes(filepath)
                    for proc in new_procs:
                        kill_process(proc.pid, force=True)
                        result.processes_killed.append(f"{proc.name} (PID: {proc.pid}) [retry]")
                    if new_procs:
                        time.sleep(self.PROCESS_KILL_WAIT)
        
        # Final verification
        result.file_still_exists = os.path.exists(filepath)
        if not result.file_still_exists:
            result.success = True
            self._log("File deleted (verified)", "success")
        else:
            result.final_error = self._diagnose_failure(filepath)
            self._log(f"All attempts failed: {result.final_error}", "error")
        
        return result
    
    def _diagnose_failure(self, filepath: str) -> str:
        """Diagnose why deletion failed."""
        reasons = []
        
        # Check if file still exists
        if not os.path.exists(filepath):
            return "File was deleted"
        
        # Check for locking processes
        procs = get_locking_processes(filepath)
        if procs:
            reasons.append(f"Still locked by: {', '.join(p.name for p in procs)}")
        
        # Check read-only
        try:
            if not os.access(filepath, os.W_OK):
                reasons.append("No write permission")
        except:
            pass
        
        # Check if system file
        try:
            attrs = kernel32.GetFileAttributesW(filepath)
            if attrs != 0xFFFFFFFF:
                if attrs & 0x4:  # FILE_ATTRIBUTE_SYSTEM
                    reasons.append("System file")
                if attrs & 0x1:  # FILE_ATTRIBUTE_READONLY
                    reasons.append("Read-only attribute")
        except:
            pass
        
        return "; ".join(reasons) if reasons else "Unknown reason"
    
    def _try_direct_delete(self, filepath: str) -> tuple[bool, Optional[str]]:
        """Simple direct deletion with os.remove."""
        try:
            os.remove(filepath)
            return True, None
        except PermissionError as e:
            return False, f"Permission denied"
        except OSError as e:
            return False, f"OS error: {e.errno}"
    
    def _try_remove_readonly(self, filepath: str) -> tuple[bool, Optional[str]]:
        """Remove read-only attribute before deletion."""
        try:
            # Get current attributes
            attrs = kernel32.GetFileAttributesW(filepath)
            if attrs == 0xFFFFFFFF:
                return False, "Cannot get file attributes"
            
            # Remove read-only if set
            if attrs & 0x1:  # FILE_ATTRIBUTE_READONLY
                new_attrs = attrs & ~0x1
                kernel32.SetFileAttributesW(filepath, new_attrs)
                self._log("Removed read-only attribute", "info")
            
            os.remove(filepath)
            return True, None
        except Exception as e:
            return False, str(e)
    
    def _try_with_permission_fix(self, filepath: str) -> tuple[bool, Optional[str]]:
        """Fix permissions using chmod before deletion."""
        try:
            # Grant full permissions
            os.chmod(filepath, stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
            os.remove(filepath)
            return True, None
        except PermissionError:
            return False, "Permission fix failed"
        except OSError as e:
            return False, f"OS error: {e.errno}"
    
    def _try_force_delete(self, filepath: str) -> tuple[bool, Optional[str]]:
        """Force delete using Windows kernel32 API."""
        try:
            # Set normal attributes first
            kernel32.SetFileAttributesW(filepath, 0x80)  # FILE_ATTRIBUTE_NORMAL
            
            # Try DeleteFileW
            result = kernel32.DeleteFileW(filepath)
            if result:
                return True, None
            else:
                error_code = ctypes.get_last_error()
                error_messages = {
                    2: "File not found",
                    5: "Access denied",
                    32: "File in use by another process",
                    33: "File locked",
                    145: "Directory not empty",
                }
                return False, error_messages.get(error_code, f"Error code {error_code}")
        except Exception as e:
            return False, str(e)
    
    def _try_rename_delete(self, filepath: str) -> tuple[bool, Optional[str]]:
        """Rename file to temp name then delete (bypasses some locks)."""
        try:
            import uuid
            temp_name = filepath + f".{uuid.uuid4().hex[:8]}.tmp"
            
            # Try to rename
            os.rename(filepath, temp_name)
            self._log(f"Renamed to temp file", "info")
            
            # Now delete the renamed file
            os.remove(temp_name)
            return True, None
        except PermissionError:
            return False, "Cannot rename - permission denied"
        except OSError as e:
            return False, f"Rename failed: {e.errno}"
    
    def close_process(self, pid: int, process_name: str, force: bool = False) -> tuple[bool, str]:
        """Close a process with logging."""
        action = "Force killing" if force else "Closing"
        self._log(f"{action} process: {process_name} (PID: {pid})", "info")
        
        success, msg = kill_process(pid, force)
        
        if success:
            self._log(f"Process {action.lower()} successful", "success")
        else:
            self._log(f"Failed: {msg}", "error")
        
        return success, msg


# ============== Scanner Thread ==============

class ScannerThread(QThread):
    progress = Signal(int, int, str)
    file_found = Signal(object)
    finished_scan = Signal(int, int)
    log_message = Signal(str)
    
    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._stop = False
    
    def stop(self):
        self._stop = True
    
    def run(self):
        files = [self.path] if os.path.isfile(self.path) else []
        if os.path.isdir(self.path):
            for root, dirs, filenames in os.walk(self.path):
                self.log_message.emit(f"Scanning directory: {root}")
                for f in filenames:
                    files.append(os.path.join(root, f))
        
        total, locked_count = len(files), 0
        self.log_message.emit(f"Total files to scan: {total}")
        
        for i, filepath in enumerate(files):
            if self._stop:
                self.log_message.emit("Scan stopped by user")
                break
            self.progress.emit(i + 1, total, filepath)
            try:
                processes = get_locking_processes(filepath)
                if processes:
                    self.file_found.emit(LockedFile(path=filepath, processes=processes))
                    locked_count += 1
            except Exception as e:
                self.log_message.emit(f"Error scanning {filepath}: {e}")
        
        self.finished_scan.emit(total if not self._stop else i + 1, locked_count)


# ============== UI Components ==============

class Toast(QLabel):
    def __init__(self, parent, message: str, toast_type: str = "info"):
        super().__init__(message, parent)
        colors = {"success": Colors.SUCCESS, "error": Colors.DANGER, "warning": Colors.WARNING, "info": Colors.ACCENT}
        color = colors.get(toast_type, Colors.ACCENT)
        self.setStyleSheet(f"""
            background-color: {Colors.BG_CARD};
            color: {color};
            font-size: 12px;
            font-weight: 600;
            padding: 10px 20px;
            border: 1px solid {color};
            border-radius: 4px;
        """)
        self.setAlignment(Qt.AlignCenter)
        self.adjustSize()
        QTimer.singleShot(2500, self.deleteLater)


class DropZone(QFrame):
    dropped = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setFixedHeight(36)
        self.setStyleSheet(f"background-color: {Colors.BG_INPUT}; border: 1px dashed {Colors.BORDER}; border-radius: 4px;")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        self.label = QLabel("Drop file or folder here...")
        self.label.setStyleSheet(f"color: {Colors.TEXT_DIM}; border: none; background: transparent;")
        layout.addWidget(self.label)
    
    def set_path(self, path: str):
        if not path:
            # Reset to initial state
            self.label.setText("Drop file or folder here...")
            self.label.setStyleSheet(f"color: {Colors.TEXT_DIM}; border: none; background: transparent;")
        else:
            self.label.setText(os.path.basename(path) or path)
            self.label.setStyleSheet(f"color: {Colors.TEXT}; border: none; background: transparent;")
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(f"background-color: {Colors.BG_INPUT}; border: 1px solid {Colors.ACCENT}; border-radius: 4px;")
    
    def dragLeaveEvent(self, event):
        self.setStyleSheet(f"background-color: {Colors.BG_INPUT}; border: 1px dashed {Colors.BORDER}; border-radius: 4px;")
    
    def dropEvent(self, event):
        self.setStyleSheet(f"background-color: {Colors.BG_INPUT}; border: 1px dashed {Colors.BORDER}; border-radius: 4px;")
        if event.mimeData().hasUrls():
            path = event.mimeData().urls()[0].toLocalFile()
            self.set_path(path)
            self.dropped.emit(path)


class LockedFileCard(QFrame):
    process_close = Signal(int, bool, str)
    auto_delete = Signal(str)
    
    def __init__(self, locked_file: LockedFile):
        super().__init__()
        self.locked_file = locked_file
        self.setStyleSheet(f"QFrame {{ background-color: {Colors.BG_CARD}; border: 1px solid {Colors.BORDER}; border-radius: 8px; }}")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        
        # Header row - filename, lock badge, and info button
        header = QHBoxLayout()
        header.setSpacing(10)
        
        filename = QLabel(locked_file.filename)
        filename.setStyleSheet(f"color: {Colors.TEXT}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        filename.setToolTip(locked_file.path)
        header.addWidget(filename)
        
        badge = QLabel(f"{len(locked_file.processes)} lock{'s' if len(locked_file.processes) > 1 else ''}")
        badge.setStyleSheet(f"background: transparent; color: {Colors.DANGER}; font-size: 11px; font-weight: bold; padding: 2px 8px; border: 1px solid {Colors.DANGER}; border-radius: 10px;")
        badge.setAlignment(Qt.AlignCenter)
        header.addWidget(badge)
        
        header.addStretch()
        
        # Info button
        info_btn = QPushButton()
        info_btn.setIcon(create_svg_icon(INFO_ICON_SVG, Colors.ACCENT, 16))
        info_btn.setIconSize(QSize(16, 16))
        info_btn.setFixedSize(24, 24)
        info_btn.setCursor(Qt.PointingHandCursor)
        info_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: rgba(155, 123, 207, 0.2);
            }}
        """)
        info_btn.setToolTip("View details")
        info_btn.clicked.connect(lambda: self._show_info())
        header.addWidget(info_btn)
        
        layout.addLayout(header)
        
        # Process rows
        for proc in locked_file.processes:
            row = QHBoxLayout()
            row.setSpacing(8)
            
            # Process name - truncate if too long
            proc_label = QLabel(proc.name[:20] + "..." if len(proc.name) > 20 else proc.name)
            proc_label.setStyleSheet(f"color: {Colors.TEXT}; font-size: 13px; font-weight: 600; border: none; background: transparent;")
            proc_label.setToolTip(proc.name)
            row.addWidget(proc_label)
            
            # PID - prominent
            pid_label = QLabel(f"PID: {proc.pid}")
            pid_label.setStyleSheet(f"color: {Colors.WARNING}; font-size: 13px; font-weight: bold; border: none; background: transparent;")
            row.addWidget(pid_label)
            
            row.addStretch()
            
            # Compact action buttons
            close_btn = QPushButton("Close")
            close_btn.setStyleSheet(BTN_PRIMARY)
            close_btn.setFixedWidth(60)
            close_btn.setCursor(Qt.PointingHandCursor)
            close_btn.clicked.connect(lambda _, p=proc.pid, fp=locked_file.path: self.process_close.emit(p, False, fp))
            row.addWidget(close_btn)
            
            force_btn = QPushButton("Force")
            force_btn.setStyleSheet(BTN_PRIMARY)
            force_btn.setFixedWidth(60)
            force_btn.setCursor(Qt.PointingHandCursor)
            force_btn.clicked.connect(lambda _, p=proc.pid, fp=locked_file.path: self.process_close.emit(p, True, fp))
            row.addWidget(force_btn)
            
            auto_btn = QPushButton("Delete")
            auto_btn.setStyleSheet(BTN_DANGER)
            auto_btn.setFixedWidth(60)
            auto_btn.setCursor(Qt.PointingHandCursor)
            auto_btn.clicked.connect(lambda: self.auto_delete.emit(locked_file.path))
            row.addWidget(auto_btn)
            
            layout.addLayout(row)
    
    def _show_info(self):
        """Show detailed info panel"""
        overlay = InfoPanel(self.window(), self.locked_file)
        overlay.show()


class InfoPanel(QWidget):
    """Centered info panel showing detailed process information"""
    
    def __init__(self, parent, locked_file: LockedFile):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setGeometry(parent.rect())
        
        # Background overlay
        self._bg = QWidget(self)
        self._bg.setGeometry(self.rect())
        self._bg.setStyleSheet("background-color: rgba(0, 0, 0, 0.6);")
        self._bg.mousePressEvent = lambda e: self.close()
        
        # Dialog panel
        dialog = QFrame(self)
        dialog.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.BG_CARD};
                border: 2px solid {Colors.ACCENT};
                border-radius: 10px;
            }}
        """)
        dialog.setFixedSize(360, 280)
        dialog.move((self.width() - 360) // 2, (self.height() - 280) // 2)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(14)
        
        # Header with icon and title
        header = QHBoxLayout()
        header.setSpacing(10)
        
        icon_btn = QLabel()
        icon_btn.setPixmap(create_svg_icon(INFO_ICON_SVG, Colors.ACCENT, 22).pixmap(22, 22))
        icon_btn.setFixedSize(22, 22)
        icon_btn.setStyleSheet("border: none; background: transparent;")
        header.addWidget(icon_btn)
        
        title = QLabel("File Lock Details")
        title.setStyleSheet(f"color: {Colors.TEXT}; font-size: 16px; font-weight: bold; border: none; background: transparent;")
        header.addWidget(title)
        header.addStretch()
        
        # Close button
        close_btn = QPushButton("×")
        close_btn.setFixedSize(24, 24)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {Colors.TEXT_DIM};
                font-size: 18px;
                font-weight: bold;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: rgba(255, 255, 255, 0.1);
                color: {Colors.TEXT};
            }}
        """)
        close_btn.clicked.connect(self.close)
        header.addWidget(close_btn)
        
        layout.addLayout(header)
        
        # File info
        file_section = QFrame()
        file_section.setStyleSheet(f"background: {Colors.BG_INPUT}; border: 1px solid {Colors.BORDER}; border-radius: 6px;")
        file_layout = QVBoxLayout(file_section)
        file_layout.setContentsMargins(12, 10, 12, 10)
        file_layout.setSpacing(6)
        
        file_label = QLabel("FILE")
        file_label.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 10px; font-weight: bold; border: none; background: transparent;")
        file_layout.addWidget(file_label)
        
        file_name = QLabel(locked_file.filename)
        file_name.setStyleSheet(f"color: {Colors.TEXT}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        file_layout.addWidget(file_name)
        
        file_path = QLabel(locked_file.path)
        file_path.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 11px; border: none; background: transparent;")
        file_path.setWordWrap(True)
        file_layout.addWidget(file_path)
        
        layout.addWidget(file_section)
        
        # Process info
        for i, proc in enumerate(locked_file.processes):
            proc_section = QFrame()
            proc_section.setStyleSheet(f"background: {Colors.BG_INPUT}; border: 1px solid {Colors.BORDER}; border-radius: 6px;")
            proc_layout = QVBoxLayout(proc_section)
            proc_layout.setContentsMargins(12, 10, 12, 10)
            proc_layout.setSpacing(4)
            
            # Process header
            proc_header = QHBoxLayout()
            proc_header.setSpacing(10)
            
            proc_title = QLabel(f"PROCESS {i+1}")
            proc_title.setStyleSheet(f"color: {Colors.ACCENT}; font-size: 10px; font-weight: bold; border: none; background: transparent;")
            proc_header.addWidget(proc_title)
            
            proc_type = QLabel(f"[{proc.type_name}]")
            proc_type.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 10px; border: none; background: transparent;")
            proc_header.addWidget(proc_type)
            proc_header.addStretch()
            proc_layout.addLayout(proc_header)
            
            # Process name
            proc_name = QLabel(proc.name)
            proc_name.setStyleSheet(f"color: {Colors.TEXT}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
            proc_name.setWordWrap(True)
            proc_layout.addWidget(proc_name)
            
            # PID
            pid_row = QHBoxLayout()
            pid_label = QLabel("PID:")
            pid_label.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 12px; border: none; background: transparent;")
            pid_row.addWidget(pid_label)
            
            pid_value = QLabel(str(proc.pid))
            pid_value.setStyleSheet(f"color: {Colors.WARNING}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
            pid_row.addWidget(pid_value)
            pid_row.addStretch()
            proc_layout.addLayout(pid_row)
            
            layout.addWidget(proc_section)
        
        layout.addStretch()


# ============== Scanner Page ==============

class ScannerPage(QWidget):
    toast_signal = Signal(str, str)
    log_signal = None
    
    def __init__(self):
        super().__init__()
        self.current_path = ""
        self.scanner: Optional[ScannerThread] = None
        self.locked_files: List[LockedFile] = []
        
        # Scan tracking for export
        self.has_scanned = False
        self.last_scan_info = {
            "timestamp": None,
            "path": None,
            "total_files": 0,
            "locked_count": 0,
            "duration": 0,
            "actions": []  # Track user actions (close, kill, delete)
        }
        self._scan_start_time = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 16)
        layout.setSpacing(12)
        
        # Top bar
        top = QHBoxLayout()
        top.setSpacing(8)
        
        self.drop_zone = DropZone()
        self.drop_zone.dropped.connect(self._on_drop)
        top.addWidget(self.drop_zone, 1)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setStyleSheet(BTN_DEFAULT)
        self.browse_btn.setCursor(Qt.PointingHandCursor)
        self.browse_btn.clicked.connect(self._browse)
        top.addWidget(self.browse_btn)
        
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setStyleSheet(BTN_PRIMARY)
        self.scan_btn.setCursor(Qt.PointingHandCursor)
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self._scan)
        top.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setStyleSheet(BTN_DANGER)
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.hide()
        top.addWidget(self.stop_btn)
        
        layout.addLayout(top)
        
        # Results area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setStyleSheet(f"""
            QScrollArea {{
                background-color: {Colors.BG};
                border: 1px solid {Colors.BORDER};
                border-radius: 6px;
            }}
            QScrollArea > QWidget > QWidget {{
                background-color: {Colors.BG};
            }}
        """)
        
        self.results = QWidget()
        self.results.setStyleSheet(f"background-color: {Colors.BG}; border: none; border-radius: 6px;")
        self.results_layout = QVBoxLayout(self.results)
        self.results_layout.setAlignment(Qt.AlignTop)
        self.results_layout.setSpacing(8)
        self.results_layout.setContentsMargins(8, 8, 8, 8)
        
        self.empty = QLabel("Drop a file or folder to scan for locks")
        self.empty.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 13px;")
        self.empty.setAlignment(Qt.AlignCenter)
        self.results_layout.addWidget(self.empty)
        
        self.scroll.setWidget(self.results)
        layout.addWidget(self.scroll, 1)
        
        # Bottom bar
        bottom = QHBoxLayout()
        
        self.progress = QProgressBar()
        self.progress.setStyleSheet(f"""
            QProgressBar {{ background-color: {Colors.BORDER}; border: none; border-radius: 2px; height: 4px; }}
            QProgressBar::chunk {{ background-color: {Colors.ACCENT}; border-radius: 2px; }}
        """)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.hide()
        
        self.status = QLabel("Ready")
        self.status.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 11px;")
        
        status_layout = QVBoxLayout()
        status_layout.setSpacing(4)
        status_layout.addWidget(self.progress)
        status_layout.addWidget(self.status)
        bottom.addLayout(status_layout, 1)
        
        reset_btn = QPushButton("Reset")
        reset_btn.setStyleSheet(BTN_DEFAULT)
        reset_btn.setCursor(Qt.PointingHandCursor)
        reset_btn.clicked.connect(self._reset)
        bottom.addWidget(reset_btn)
        
        export_btn = QPushButton("Export")
        export_btn.setStyleSheet(BTN_DEFAULT)
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self._export)
        bottom.addWidget(export_btn)
        
        layout.addLayout(bottom)
    
    def _on_drop(self, path):
        self.current_path = path
        self.scan_btn.setEnabled(True)
    
    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            self.current_path = path
            self.drop_zone.set_path(path)
            self.scan_btn.setEnabled(True)
    
    def _scan(self):
        if not self.current_path:
            return
        self._clear()
        self.locked_files = []
        self.scan_btn.hide()
        self.stop_btn.show()
        self.progress.show()
        self.progress.setValue(0)
        
        # Reset scan tracking
        self._scan_start_time = time.time()
        self.last_scan_info = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "path": self.current_path,
            "total_files": 0,
            "locked_count": 0,
            "duration": 0,
            "actions": []
        }
        
        if self.log_signal:
            self.log_signal.log_scan_start(self.current_path)
        
        self.scanner = ScannerThread(self.current_path)
        self.scanner.progress.connect(lambda s, t, f: (self.progress.setValue(int(s/t*100) if t else 0), self.status.setText(f"Scanning: {s}/{t}")))
        self.scanner.file_found.connect(self._add_file)
        self.scanner.finished_scan.connect(self._done)
        self.scanner.log_message.connect(self._log_msg)
        self.scanner.start()
    
    def _log_msg(self, msg):
        if self.log_signal:
            self.log_signal.log(msg, "info")
    
    def _stop(self):
        if self.scanner:
            self.scanner.stop()
    
    def _add_file(self, lf):
        self.empty.hide()
        self.locked_files.append(lf)
        card = LockedFileCard(lf)
        card.process_close.connect(self._close_proc)
        card.auto_delete.connect(self._auto_del)
        self.results_layout.addWidget(card)
        
        if self.log_signal:
            self.log_signal.log_locked_file(lf)
    
    def _done(self, total, locked):
        self.stop_btn.hide()
        self.scan_btn.show()
        self.progress.hide()
        self.status.setText(f"{total} scanned, {locked} locked")
        
        # Update scan info
        self.has_scanned = True
        self.last_scan_info["total_files"] = total
        self.last_scan_info["locked_count"] = locked
        if self._scan_start_time:
            self.last_scan_info["duration"] = round(time.time() - self._scan_start_time, 2)
        
        # Update empty label if no locked files found
        if locked == 0:
            self.empty.setText("No locked files found")
            self.empty.show()
        
        if self.log_signal:
            self.log_signal.log_scan_end(total, locked)
        
        msg = "No locked files found" if locked == 0 else f"Found {locked} locked file{'s' if locked > 1 else ''}"
        self.toast_signal.emit(msg, "success" if locked == 0 else "info")
    
    def _close_proc(self, pid, force, fp):
        # Find process name from locked files
        proc_name = "Unknown"
        for lf in self.locked_files:
            if lf.path == fp:
                for p in lf.processes:
                    if p.pid == pid:
                        proc_name = p.name
                        break
        
        def on_confirm(result):
            if result:
                action = "Force Kill" if force else "Close"
                
                # Log action start
                if self.log_signal:
                    self.log_signal.log_action_start(action, fp, f"{proc_name} (PID: {pid})")
                
                ok, msg = kill_process(pid, force)
                
                # Log result
                if self.log_signal:
                    self.log_signal.log_process_action(action, proc_name, pid, ok, "" if ok else msg)
                
                # Track action for export
                self.last_scan_info["actions"].append({
                    "type": action,
                    "target": fp,
                    "process": proc_name,
                    "pid": pid,
                    "success": ok,
                    "error": msg if not ok else None,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
                # Short toast message
                if ok:
                    self.toast_signal.emit(f"Process closed - see Log", "success")
                    self._refresh(fp)
                else:
                    self.toast_signal.emit(f"Failed - check Log", "error")
        
        overlay = ModalOverlay(self.window())
        overlay.show_confirm(
            "Close Process" if not force else "Force Kill Process",
            f"{'Force kill' if force else 'Close'} process with PID {pid}?",
            danger=force,
            callback=on_confirm
        )
    
    def _auto_del(self, fp):
        def on_confirm(confirmed):
            if confirmed:
                filename = os.path.basename(fp)
                
                # Log action start
                if self.log_signal:
                    self.log_signal.log_action_start("Delete", fp, filename)
                
                # Create smart deleter with logging
                def log_callback(msg, level):
                    if self.log_signal:
                        self.log_signal.log(msg, level)
                
                deleter = SmartFileDeleter(log_callback)
                result = deleter.delete_file(fp, kill_processes=True)
                
                # Log final result
                if self.log_signal:
                    self.log_signal.log_delete_result(
                        fp, 
                        result.success, 
                        len(result.attempts),
                        result.processes_killed
                    )
                
                # Track action for export
                self.last_scan_info["actions"].append({
                    "type": "Delete",
                    "target": fp,
                    "success": result.success,
                    "attempts": len(result.attempts),
                    "strategies_tried": [a.strategy for a in result.attempts],
                    "processes_killed": result.processes_killed,
                    "error": result.final_error if not result.success else None,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
                # Short toast message
                if result.success:
                    self.toast_signal.emit("File deleted - see Log", "success")
                    self._remove(fp)
                else:
                    self.toast_signal.emit("Delete failed - check Log", "error")
        
        overlay = ModalOverlay(self.window())
        overlay.show_confirm(
            "Delete File",
            f"Kill all processes and DELETE file?\n{os.path.basename(fp)}",
            danger=True,
            callback=on_confirm
        )
    
    def _refresh(self, fp):
        if not get_locking_processes(fp):
            self._remove(fp)
    
    def _remove(self, fp):
        for i in range(self.results_layout.count()):
            w = self.results_layout.itemAt(i).widget()
            if isinstance(w, LockedFileCard) and w.locked_file.path == fp:
                w.deleteLater()
                self.locked_files = [f for f in self.locked_files if f.path != fp]
                break
    
    def _clear(self):
        while self.results_layout.count():
            if (w := self.results_layout.takeAt(0).widget()):
                w.deleteLater()
        self.empty = QLabel("Scanning...")
        self.empty.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 13px;")
        self.empty.setAlignment(Qt.AlignCenter)
        self.results_layout.addWidget(self.empty)
    
    def _reset(self):
        """Reset the entire application state to initial."""
        # Check if already in initial state
        if not self.has_scanned and not self.locked_files and not self.current_path:
            return self.toast_signal.emit("Already reset", "info")
        
        # Clear results
        while self.results_layout.count():
            if (w := self.results_layout.takeAt(0).widget()):
                w.deleteLater()
        
        # Reset empty label to initial state
        self.empty = QLabel("Drop a file or folder to scan for locks")
        self.empty.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 13px;")
        self.empty.setAlignment(Qt.AlignCenter)
        self.results_layout.addWidget(self.empty)
        
        # Clear data
        self.locked_files = []
        self.current_path = ""
        self.has_scanned = False
        self.last_scan_info = {
            "timestamp": None,
            "path": None,
            "total_files": 0,
            "locked_count": 0,
            "duration": 0,
            "actions": []
        }
        self._scan_start_time = None
        
        # Reset UI
        self.drop_zone.set_path("")  # Clear drop zone
        self.scan_btn.setEnabled(False)
        self.status.setText("Ready")
        self.progress.hide()
        self.progress.setValue(0)
        
        # Clear log
        if self.log_signal:
            self.log_signal._clear()
        
        self.toast_signal.emit("Reset complete", "success")
    
    def _export(self):
        # Check if scan has been performed
        if not self.has_scanned:
            return self.toast_signal.emit("Please run a scan first", "warning")
        
        if not self.locked_files and not self.last_scan_info["actions"]:
            return self.toast_signal.emit("No data to export", "warning")
        
        # Get save path - default to detailed report name
        default_name = f"unlock_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", default_name,
            "Text Report (*.txt);;CSV Data (*.csv);;All Files (*.*)"
        )
        
        if not path:
            return
        
        try:
            with open(path, 'w', encoding='utf-8') as f:
                self._write_detailed_report(f)
            self.toast_signal.emit("Report exported", "success")
        except Exception as e:
            self.toast_signal.emit(f"Export failed: {str(e)[:30]}", "error")
    
    def _write_detailed_report(self, f):
        """Generate a comprehensive report file."""
        info = self.last_scan_info
        
        # Header
        f.write("=" * 70 + "\n")
        f.write("                    UNLOCK INSPECTOR - SCAN REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        # Scan Summary
        f.write("SCAN SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Scan Date/Time:     {info['timestamp']}\n")
        f.write(f"Target Path:        {info['path']}\n")
        f.write(f"Total Files:        {info['total_files']}\n")
        f.write(f"Locked Files Found: {info['locked_count']}\n")
        f.write(f"Scan Duration:      {info['duration']} seconds\n")
        f.write(f"Actions Performed:  {len(info['actions'])}\n")
        f.write("\n")
        
        # System Info
        f.write("SYSTEM INFORMATION\n")
        f.write("-" * 40 + "\n")
        f.write(f"Report Generated:   {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Computer Name:      {os.environ.get('COMPUTERNAME', 'Unknown')}\n")
        f.write(f"Username:           {os.environ.get('USERNAME', 'Unknown')}\n")
        f.write(f"Windows Version:    {os.environ.get('OS', 'Unknown')}\n")
        f.write("\n")
        
        # Locked Files Details
        if self.locked_files:
            f.write("=" * 70 + "\n")
            f.write("                         LOCKED FILES DETAILS\n")
            f.write("=" * 70 + "\n\n")
            
            for idx, lf in enumerate(self.locked_files, 1):
                f.write(f"[FILE {idx}]\n")
                f.write("-" * 40 + "\n")
                f.write(f"File Name:      {lf.filename}\n")
                f.write(f"Full Path:      {lf.path}\n")
                
                # File metadata
                try:
                    stat_info = os.stat(lf.path)
                    f.write(f"File Size:      {self._format_size(stat_info.st_size)}\n")
                    f.write(f"Modified:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime))}\n")
                    f.write(f"Created:        {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_ctime))}\n")
                except:
                    f.write(f"File Size:      Unable to retrieve\n")
                
                f.write(f"Lock Count:     {len(lf.processes)} process(es)\n")
                f.write("\n")
                
                # Process details
                f.write("  LOCKING PROCESSES:\n")
                for pidx, proc in enumerate(lf.processes, 1):
                    f.write(f"  [{pidx}] {proc.name}\n")
                    f.write(f"      PID:          {proc.pid}\n")
                    f.write(f"      Type:         {proc.type_name}\n")
                    f.write(f"      App Type ID:  {proc.app_type}\n")
                f.write("\n")
        else:
            f.write("=" * 70 + "\n")
            f.write("                         NO LOCKED FILES\n")
            f.write("=" * 70 + "\n")
            f.write("No locked files were found during this scan session.\n")
            f.write("\n")
        
        # Actions Performed
        if info['actions']:
            f.write("=" * 70 + "\n")
            f.write("                         ACTIONS PERFORMED\n")
            f.write("=" * 70 + "\n\n")
            
            for idx, action in enumerate(info['actions'], 1):
                status = "SUCCESS" if action['success'] else "FAILED"
                f.write(f"[ACTION {idx}] {action['type']} - {status}\n")
                f.write("-" * 40 + "\n")
                f.write(f"Timestamp:      {action['timestamp']}\n")
                f.write(f"Target:         {action['target']}\n")
                
                if action['type'] in ['Close', 'Force Kill']:
                    f.write(f"Process:        {action.get('process', 'N/A')}\n")
                    f.write(f"PID:            {action.get('pid', 'N/A')}\n")
                elif action['type'] == 'Delete':
                    f.write(f"Attempts:       {action.get('attempts', 'N/A')}\n")
                    strategies = action.get('strategies_tried', [])
                    if strategies:
                        f.write(f"Strategies:     {', '.join(strategies)}\n")
                    procs = action.get('processes_killed', [])
                    if procs:
                        f.write(f"Killed Procs:   {', '.join(procs)}\n")
                
                if action.get('error'):
                    f.write(f"Error:          {action['error']}\n")
                
                f.write("\n")
        
        # Statistics
        f.write("=" * 70 + "\n")
        f.write("                            STATISTICS\n")
        f.write("=" * 70 + "\n\n")
        
        total_actions = len(info['actions'])
        success_actions = sum(1 for a in info['actions'] if a['success'])
        failed_actions = total_actions - success_actions
        
        close_actions = [a for a in info['actions'] if a['type'] in ['Close', 'Force Kill']]
        delete_actions = [a for a in info['actions'] if a['type'] == 'Delete']
        
        f.write(f"Total Actions:          {total_actions}\n")
        f.write(f"Successful:             {success_actions}\n")
        f.write(f"Failed:                 {failed_actions}\n")
        f.write(f"Process Close/Kill:     {len(close_actions)}\n")
        f.write(f"File Deletions:         {len(delete_actions)}\n")
        
        if total_actions > 0:
            success_rate = (success_actions / total_actions) * 100
            f.write(f"Success Rate:           {success_rate:.1f}%\n")
        
        f.write("\n")
        
        # Footer
        f.write("=" * 70 + "\n")
        f.write("                          END OF REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Generated by Unlock Inspector | {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable size."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}" if unit != 'B' else f"{size_bytes} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} PB"


# ============== Log Page ==============

class LogPage(QWidget):
    # Log colors - more vibrant and distinct
    LOG_COLORS = {
        "info": "#64b5f6",       # Blue
        "debug": "#90a4ae",      # Gray
        "warn": "#ffb74d",       # Orange
        "error": "#ef5350",      # Red
        "success": "#81c784",    # Green
        "lock": "#ce93d8",       # Purple (lock detection)
        "file": "#4dd0e1",       # Cyan (file paths)
        "process": "#ffab91",    # Coral (process names) - NEW
        "pid": "#ffd54f",        # Yellow (PID) - NEW
        "time": "#616161",       # Dark gray
        "divider": "#9b7bcf",    # Accent purple
    }
    
    def __init__(self):
        super().__init__()
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 16)
        layout.setSpacing(12)
        
        # Top bar - mirrors Scanner page layout
        top = QHBoxLayout()
        top.setSpacing(8)
        
        # Title box matching DropZone width
        title_box = QFrame()
        title_box.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.BG_CARD};
                border: none;
                border-radius: 6px;
            }}
        """)
        title_layout = QHBoxLayout(title_box)
        title_layout.setContentsMargins(12, 8, 12, 8)
        title = QLabel("Scan Log")
        title.setStyleSheet(f"color: {Colors.TEXT}; font-size: 13px; font-weight: bold;")
        title_layout.addWidget(title)
        top.addWidget(title_box, 1)
        
        copy_btn = QPushButton("Copy")
        copy_btn.setStyleSheet(BTN_DEFAULT)
        copy_btn.setCursor(Qt.PointingHandCursor)
        copy_btn.clicked.connect(self._copy_all)
        top.addWidget(copy_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(BTN_PRIMARY)
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self._clear)
        top.addWidget(clear_btn)
        
        layout.addLayout(top)
        
        # Log output - matches scroll area position
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet(f"""
            QTextEdit {{
                background-color: #0d0d0d;
                color: #b0b0b0;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid {Colors.BORDER};
                border-radius: 6px;
                padding: 12px;
                selection-background-color: {Colors.ACCENT};
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 2px;
            }}
            QScrollBar::handle:vertical {{
                background: rgba(155, 123, 207, 0.4);
                border-radius: 4px;
                min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgba(155, 123, 207, 0.6);
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
        """)
        self._append_welcome()
        layout.addWidget(self.output, 1)
    
    def _append_welcome(self):
        c = self.LOG_COLORS
        self.output.append(f'<span style="color: {c["divider"]};">╔══════════════════════════════════════════════════════════╗</span>')
        self.output.append(f'<span style="color: {Colors.TEXT}; font-weight: bold;">                      UNLOCK INSPECTOR</span>')
        self.output.append(f'<span style="color: {Colors.TEXT_DIM};">                Ready to scan for locked files</span>')
        self.output.append(f'<span style="color: {c["divider"]};">╚══════════════════════════════════════════════════════════╝</span>')
        self.output.append('')
    
    def _ts(self) -> str:
        return time.strftime("%H:%M:%S")
    
    def _colored(self, text: str, color: str) -> str:
        return f'<span style="color: {color};">{text}</span>'
    
    def _bold(self, text: str, color: str) -> str:
        return f'<span style="color: {color}; font-weight: bold;">{text}</span>'
    
    def log(self, message: str, level: str = "info"):
        c = self.LOG_COLORS
        color = c.get(level, c["info"])
        
        tags = {
            "info": "INFO ",
            "debug": "DEBUG", 
            "warn": "WARN ",
            "error": "ERROR",
            "success": " OK  ",
            "lock": "LOCK ",
            "file": "FILE ",
        }
        tag = tags.get(level, "INFO ")
        
        line = f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold(f"[{tag}]", color)} {self._colored(message, color)}'
        self.output.append(line)
        self.output.moveCursor(QTextCursor.End)
    
    def log_locked_file(self, lf: LockedFile):
        c = self.LOG_COLORS
        
        self.output.append('')
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold("[LOCK ]", c["lock"])} {self._bold("━━━ LOCKED FILE DETECTED ━━━", c["lock"])}')
        self.output.append('')
        
        # File section
        self.output.append(f'    {self._colored("┌─ FILE ─────────────────────────────────────────", c["divider"])}')
        self.output.append(f'    {self._colored("│", c["divider"])}  {self._colored("Name:", c["time"])}  {self._bold(lf.filename, Colors.TEXT)}')
        self.output.append(f'    {self._colored("│", c["divider"])}  {self._colored("Path:", c["time"])}  {self._colored(lf.path, c["file"])}')
        self.output.append(f'    {self._colored("│", c["divider"])}  {self._colored("Locks:", c["time"])} {self._bold(str(len(lf.processes)), c["warn"])}')
        self.output.append(f'    {self._colored("└─────────────────────────────────────────────────", c["divider"])}')
        self.output.append('')
        
        # Process section for each process
        for i, p in enumerate(lf.processes):
            self.output.append(f'    {self._colored("┌─ PROCESS " + str(i+1) + " ─────────────────────────────────────", c["divider"])}')
            self.output.append(f'    {self._colored("│", c["divider"])}')
            self.output.append(f'    {self._colored("│", c["divider"])}    {self._colored("Name:", c["time"])}    {self._bold(p.name, c["process"])}')
            self.output.append(f'    {self._colored("│", c["divider"])}    {self._bold("PID:", c["time"])}     {self._bold(str(p.pid), c["pid"])}')
            self.output.append(f'    {self._colored("│", c["divider"])}    {self._colored("Type:", c["time"])}    {self._colored(p.type_name, c["info"])}')
            self.output.append(f'    {self._colored("│", c["divider"])}')
            self.output.append(f'    {self._colored("└──────────────────────────────────────────────────", c["divider"])}')
        
        self.output.append('')
        self.output.moveCursor(QTextCursor.End)
    
    def log_scan_start(self, path: str):
        c = self.LOG_COLORS
        
        self.output.append('')
        self.output.append(f'{self._bold("╔══════════════════════════════════════════════════════════╗", c["success"])}')
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold("[START]", c["success"])} {self._bold("Scan started", c["success"])}')
        self.output.append(f'            {self._colored("Target:", c["time"])} {self._colored(path, c["file"])}')
        self.output.append(f'{self._bold("╚══════════════════════════════════════════════════════════╝", c["success"])}')
        self.output.append('')
        self.output.moveCursor(QTextCursor.End)
    
    def log_scan_end(self, total: int, locked: int):
        c = self.LOG_COLORS
        c_result = c["success"] if locked == 0 else c["warn"]
        
        self.output.append('')
        self.output.append(f'{self._bold("╔══════════════════════════════════════════════════════════╗", c_result)}')
        status = "COMPLETE - No locks found" if locked == 0 else f"COMPLETE - {locked} locked file(s) found"
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold("[ END ]", c_result)} {self._bold(status, c_result)}')
        self.output.append('')
        self.output.append(f'            {self._colored("Total scanned:", c["time"])}  {self._bold(str(total), Colors.TEXT)}')
        self.output.append(f'            {self._colored("Locked files:", c["time"])}  {self._bold(str(locked), c_result)}')
        self.output.append('')
        self.output.append(f'{self._bold("╚══════════════════════════════════════════════════════════╝", c_result)}')
        self.output.append('')
        self.output.moveCursor(QTextCursor.End)
    
    def _copy_all(self):
        QApplication.clipboard().setText(self.output.toPlainText())
    
    def _clear(self):
        self.output.clear()
        self._append_welcome()
    
    # ===== Action Logging Methods =====
    
    def log_action_start(self, action: str, target: str, details: str = ""):
        """Log the start of an action (Close, Force, Delete)."""
        c = self.LOG_COLORS
        action_colors = {
            "close": c["info"],
            "force": c["warn"],
            "delete": c["error"],
        }
        color = action_colors.get(action.lower(), c["info"])
        
        self.output.append('')
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold(f"[{action.upper():6}]", color)} {self._bold(f"Starting {action}...", color)}')
        self.output.append(f'            {self._colored("Target:", c["time"])} {self._colored(target, c["file"])}')
        if details:
            self.output.append(f'            {self._colored("Details:", c["time"])} {self._colored(details, c["process"])}')
        self.output.moveCursor(QTextCursor.End)
    
    def log_action_result(self, action: str, success: bool, message: str):
        """Log the result of an action."""
        c = self.LOG_COLORS
        color = c["success"] if success else c["error"]
        status = "SUCCESS" if success else "FAILED"
        
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold(f"[{status:6}]", color)} {self._colored(message, color)}')
        self.output.append('')
        self.output.moveCursor(QTextCursor.End)
    
    def log_process_action(self, action: str, process_name: str, pid: int, success: bool, error: str = ""):
        """Log a process-related action (close/force kill)."""
        c = self.LOG_COLORS
        color = c["success"] if success else c["error"]
        
        self.output.append('')
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._bold(f"[PROC  ]", c["process"])} {self._bold(action, c["info"])}')
        self.output.append(f'            {self._colored("Process:", c["time"])} {self._bold(process_name, c["process"])}')
        self.output.append(f'            {self._colored("PID:", c["time"])}     {self._bold(str(pid), c["pid"])}')
        
        if success:
            self.output.append(f'            {self._colored("Status:", c["time"])}  {self._bold("SUCCESS", c["success"])}')
        else:
            self.output.append(f'            {self._colored("Status:", c["time"])}  {self._bold("FAILED", c["error"])}')
            if error:
                self.output.append(f'            {self._colored("Error:", c["time"])}   {self._colored(error, c["error"])}')
        
        self.output.append('')
        self.output.moveCursor(QTextCursor.End)
    
    def log_delete_attempt(self, filepath: str, attempt: int, strategy: str, success: bool, error: str = ""):
        """Log a file deletion attempt."""
        c = self.LOG_COLORS
        color = c["success"] if success else c["warn"]
        
        self.output.append(f'{self._colored(f"[{self._ts()}]", c["time"])} {self._colored(f"[ATT {attempt}]", c["info"])} {self._colored(f"Strategy: {strategy}", color)}')
        if not success and error:
            self.output.append(f'            {self._colored("Reason:", c["time"])}  {self._colored(error, c["warn"])}')
        self.output.moveCursor(QTextCursor.End)
    
    def log_delete_result(self, filepath: str, success: bool, attempts: int, processes_killed: List[str] = None):
        """Log the final result of a file deletion."""
        c = self.LOG_COLORS
        filename = os.path.basename(filepath)
        
        self.output.append('')
        if success:
            self.output.append(f'{self._bold("┌─ DELETE SUCCESSFUL ────────────────────────────", c["success"])}')
            self.output.append(f'{self._colored("│", c["success"])}  {self._colored("File:", c["time"])}     {self._bold(filename, Colors.TEXT)}')
            self.output.append(f'{self._colored("│", c["success"])}  {self._colored("Attempts:", c["time"])} {self._colored(str(attempts), c["info"])}')
            if processes_killed:
                self.output.append(f'{self._colored("│", c["success"])}  {self._colored("Killed:", c["time"])}   {self._colored(", ".join(processes_killed), c["process"])}')
            self.output.append(f'{self._bold("└─────────────────────────────────────────────────", c["success"])}')
        else:
            self.output.append(f'{self._bold("┌─ DELETE FAILED ────────────────────────────────", c["error"])}')
            self.output.append(f'{self._colored("│", c["error"])}  {self._colored("File:", c["time"])}     {self._bold(filename, Colors.TEXT)}')
            self.output.append(f'{self._colored("│", c["error"])}  {self._colored("Path:", c["time"])}     {self._colored(filepath, c["file"])}')
            self.output.append(f'{self._colored("│", c["error"])}  {self._colored("Attempts:", c["time"])} {self._colored(str(attempts), c["warn"])}')
            self.output.append(f'{self._colored("│", c["error"])}')
            self.output.append(f'{self._colored("│", c["error"])}  {self._bold("File could not be deleted. Possible causes:", c["warn"])}')
            self.output.append(f'{self._colored("│", c["error"])}  - Process respawned after being killed')
            self.output.append(f'{self._colored("│", c["error"])}  - System file or protected resource')
            self.output.append(f'{self._colored("│", c["error"])}  - Insufficient permissions')
            self.output.append(f'{self._bold("└─────────────────────────────────────────────────", c["error"])}')
        
        self.output.append('')
        self.output.moveCursor(QTextCursor.End)


# ============== Info Page ==============

class InfoPage(QWidget):
    """Application usage guide page"""
    
    def __init__(self):
        super().__init__()
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 16)
        layout.setSpacing(12)
        
        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                background-color: {Colors.BG};
                border: 1px solid {Colors.BORDER};
                border-radius: 6px;
            }}
            QScrollArea > QWidget > QWidget {{
                background-color: {Colors.BG};
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 4px 2px 4px 2px;
            }}
            QScrollBar::handle:vertical {{
                background: rgba(155, 123, 207, 0.4);
                border-radius: 4px;
                min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgba(155, 123, 207, 0.6);
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
        """)
        
        content = QWidget()
        content.setStyleSheet(f"background-color: {Colors.BG}; border: none;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(16, 16, 16, 16)
        content_layout.setSpacing(16)
        
        # Title section
        title_frame = QFrame()
        title_frame.setStyleSheet(f"background: {Colors.BG_CARD}; border: 1px solid {Colors.ACCENT}; border-radius: 8px;")
        title_layout = QVBoxLayout(title_frame)
        title_layout.setContentsMargins(16, 14, 16, 14)
        title_layout.setSpacing(8)
        
        title = QLabel("Unlock Inspector")
        title.setStyleSheet(f"color: {Colors.ACCENT}; font-size: 18px; font-weight: bold; border: none; background: transparent;")
        title.setAlignment(Qt.AlignCenter)
        title_layout.addWidget(title)
        
        subtitle = QLabel("File Lock Detection & Process Management Tool")
        subtitle.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 12px; border: none; background: transparent;")
        subtitle.setAlignment(Qt.AlignCenter)
        title_layout.addWidget(subtitle)
        
        content_layout.addWidget(title_frame)
        
        # Quick Start section
        self._add_section(content_layout, "Quick Start", [
            ("1.", "Drop a file or folder into the drop zone, or click", "Browse", "to select a folder."),
            ("2.", "Click", "Scan", "to detect locked files in the selected path."),
            ("3.", "View locked files and the processes holding them."),
            ("4.", "Use action buttons to manage locks."),
        ])
        
        # Features section
        self._add_section(content_layout, "Features", [
            ("Scanner", "Scans files and folders to detect which processes are locking them."),
            ("Log", "Detailed scan history with process and PID information."),
            ("Info Panel", "Click the info icon on any locked file for detailed information."),
        ])
        
        # Action Buttons section
        self._add_section(content_layout, "Action Buttons", [
            ("Close", "Gracefully close the process holding the file lock.", Colors.ACCENT),
            ("Force", "Forcefully terminate the process (use with caution).", Colors.ACCENT),
            ("Delete", "Kill all locking processes and delete the file.", Colors.DANGER),
            ("Reset", "Clear all results and logs, reset app to initial state.", Colors.TEXT_DIM),
            ("Export", "Export detailed scan report with file info and actions.", Colors.TEXT_DIM),
        ])
        
        # Tips section
        tips_frame = QFrame()
        tips_frame.setStyleSheet(f"background: {Colors.BG_CARD}; border: 1px solid {Colors.WARNING}; border-radius: 8px;")
        tips_layout = QVBoxLayout(tips_frame)
        tips_layout.setContentsMargins(16, 12, 16, 12)
        tips_layout.setSpacing(8)
        
        tips_title = QLabel("Tips")
        tips_title.setStyleSheet(f"color: {Colors.WARNING}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        tips_layout.addWidget(tips_title)
        
        tips = [
            "Drag and drop files directly onto the drop zone for quick scanning.",
            "Use the Log tab to track all scan activities and results.",
            "Force kill should be used carefully - unsaved data may be lost.",
            "Export generates a detailed report with file info, processes, and actions.",
            "Use Reset to clear everything and start fresh with a new folder.",
        ]
        for tip in tips:
            tip_label = QLabel(f"• {tip}")
            tip_label.setStyleSheet(f"color: {Colors.TEXT}; font-size: 12px; border: none; background: transparent;")
            tip_label.setWordWrap(True)
            tips_layout.addWidget(tip_label)
        
        content_layout.addWidget(tips_frame)
        
        # Tech info
        tech_frame = QFrame()
        tech_frame.setStyleSheet(f"background: {Colors.BG_CARD}; border: 1px solid {Colors.BORDER}; border-radius: 8px;")
        tech_layout = QVBoxLayout(tech_frame)
        tech_layout.setContentsMargins(16, 12, 16, 12)
        tech_layout.setSpacing(6)
        
        tech_title = QLabel("Technical Info")
        tech_title.setStyleSheet(f"color: {Colors.TEXT}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        tech_layout.addWidget(tech_title)
        
        tech_text = QLabel("This tool uses the Windows Restart Manager API to detect which processes are holding file locks. It provides a safe way to identify and manage locked files without restarting your computer.")
        tech_text.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 12px; border: none; background: transparent;")
        tech_text.setWordWrap(True)
        tech_layout.addWidget(tech_text)
        
        content_layout.addWidget(tech_frame)
        
        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)
    
    def _add_section(self, parent_layout, title: str, items: list):
        frame = QFrame()
        frame.setStyleSheet(f"background: {Colors.BG_CARD}; border: 1px solid {Colors.BORDER}; border-radius: 8px;")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {Colors.TEXT}; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        layout.addWidget(title_label)
        
        for item in items:
            row = QHBoxLayout()
            row.setSpacing(6)
            
            if len(item) == 4:  # Step format: (num, text, highlight, text)
                num, text1, highlight, text2 = item
                label = QLabel(f'<span style="color: {Colors.ACCENT}; font-weight: bold;">{num}</span> '
                              f'<span style="color: {Colors.TEXT};">{text1}</span> '
                              f'<span style="color: {Colors.ACCENT}; font-weight: bold;">{highlight}</span> '
                              f'<span style="color: {Colors.TEXT};">{text2}</span>')
            elif len(item) == 3 and isinstance(item[2], str) and item[2].startswith("#"):  # Button format with color
                name, desc, color = item
                label = QLabel(f'<span style="color: {color}; font-weight: bold;">{name}</span>'
                              f'<span style="color: {Colors.TEXT};"> - {desc}</span>')
            elif len(item) == 3:  # Step without highlight
                num, text1, text2 = item
                label = QLabel(f'<span style="color: {Colors.ACCENT}; font-weight: bold;">{num}</span> '
                              f'<span style="color: {Colors.TEXT};">{text1} {text2}</span>')
            else:  # Feature format: (name, desc)
                name, desc = item
                label = QLabel(f'<span style="color: {Colors.ACCENT}; font-weight: bold;">{name}</span>'
                              f'<span style="color: {Colors.TEXT};"> - {desc}</span>')
            
            label.setStyleSheet("border: none; background: transparent; font-size: 12px;")
            label.setWordWrap(True)
            row.addWidget(label)
            layout.addLayout(row)
        
        parent_layout.addWidget(frame)


# ============== Main Window ==============

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unlock Inspector")
        self.setFixedSize(580, 520)
        self.setStyleSheet(f"background-color: {Colors.BG};")
        self._setup_ui()
    
    def _toast(self, msg: str, t: str = "info"):
        toast = Toast(self.scanner_page.scroll, msg, t)
        scroll_rect = self.scanner_page.scroll.rect()
        toast.move((scroll_rect.width() - toast.width()) // 2, scroll_rect.height() - toast.height() - 20)
        toast.show()
        toast.raise_()
    
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {Colors.BG};
            }}
            QTabBar {{
                background-color: {Colors.BG};
            }}
            QTabBar::tab {{
                background-color: transparent;
                color: {Colors.ACCENT};
                font-size: 11px;
                font-weight: 600;
                padding: 6px 14px;
                border: 1px solid {Colors.ACCENT};
                border-radius: 4px;
                margin: 10px 4px 10px 0px;
                min-width: 50px;
            }}
            QTabBar::tab:first {{
                margin-left: 16px;
            }}
            QTabBar::tab:selected {{
                color: {Colors.BG};
                background-color: {Colors.ACCENT};
            }}
            QTabBar::tab:hover:!selected {{
                background-color: rgba(155, 123, 207, 0.15);
            }}
        """)
        
        self.scanner_page = ScannerPage()
        self.scanner_page.toast_signal.connect(self._toast)
        self.tabs.addTab(self.scanner_page, "Scanner")
        
        self.log_page = LogPage()
        self.tabs.addTab(self.log_page, "Log")
        
        self.info_page = InfoPage()
        self.tabs.addTab(self.info_page, "Info")
        
        self.scanner_page.log_signal = self.log_page
        
        layout.addWidget(self.tabs, 1)
        
        # Info footer
        footer = QLabel("by fleur  •  v1.0  •  Detects processes locking files using Windows Restart Manager API")
        footer.setStyleSheet(f"color: {Colors.TEXT_DIM}; font-size: 10px; padding: 8px;")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer)


if __name__ == "__main__":
    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application-wide font with better rendering
    font = QFont("Segoe UI", 9)
    font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
