"""
路径工具模块(项目统一路径配置) ===
- 提供项目根路径 BASE_DIR
- 避免各模块重复 .parent.parent 结构
"""
from pathlib import Path

# 获取当前文件位置(path_utils.py)
CURRENT_FILE = Path(__file__).resolve()

# 项目根路径: openai_chat/
BASE_DIR = CURRENT_FILE.parent.parent.parent.parent

# 对外导出
__all__ = ["BASE_DIR"]