#!/usr/bin/env python
"""运行所有单元测试的脚本。"""

import subprocess
import sys


def main():
    """运行所有测试目录下的测试。"""
    test_paths = [
        "anp/unittest/",
        "anp/anp_crawler/test/",
        "anp/fastanp/",
    ]

    cmd = ["uv", "run", "pytest"] + test_paths + sys.argv[1:]
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
