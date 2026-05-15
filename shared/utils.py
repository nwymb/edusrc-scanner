"""共享工具函数"""

import re

# crt.sh JSON 控制字符清理
JSON_CLEAN_RE = re.compile(r"[\x00-\x1f\x7f]")
