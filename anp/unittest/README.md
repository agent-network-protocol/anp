# ANP Unit Tests

本目录包含 ANP (Agent Network Protocol) 的单元测试。

## 测试结构

```
anp/unittest/
├── __init__.py                       # 测试包初始化
├── README.md                        # 本文件
├── TESTING_SUMMARY.md               # 测试总结文档
└── authentication/                  # 身份认证测试模块
    ├── __init__.py                  # 模块初始化
    ├── test_authentication.py       # 身份认证测试套件 (19个测试)
    └── README.md                    # 模块说明文档
```

## 测试模块

### authentication/ - 身份认证测试

完整的 DID WBA 身份认证测试,包含:
- DID 文档创建和验证
- 版本兼容性测试 (1.0, 1.1, 1.2)
- 跨版本认证场景
- HTTP 和 JSON 格式认证
- 使用公共测试数据验证

**测试数量**: 19 个测试,6 个测试类

详细信息请查看 [authentication/README.md](authentication/README.md)

## 快速开始

### 运行所有测试
```bash
uv run pytest anp/unittest/ -v
```

### 运行特定模块测试
```bash
# 运行身份认证测试
uv run pytest anp/unittest/authentication/ -v
```

### 查看测试覆盖率
```bash
uv run pytest anp/unittest/ --cov=anp --cov-report=html
```

## 测试原则

所有测试遵循以下原则:

1. **不使用 mock**: 所有测试使用真实函数调用和真实加密操作
2. **独立测试**: 每个测试独立运行,无执行顺序依赖
3. **快速执行**: 单个测试 < 100ms,整个套件 < 1秒
4. **清晰命名**:
   - 测试类: `Test<功能名称>`
   - 测试方法: `test_<具体场景>`
5. **充分文档**: 使用文档字符串说明测试目的
6. **有用断言**: 断言消息提供失败时的上下文信息

## 测试数据

测试使用的公共数据位于:
- **DID 文档**: `docs/did_public/public-did-doc.json`
- **私钥**: `docs/did_public/public-private-key.pem`

这些是专门用于测试的公共密钥对,不应在生产环境使用。

## 目录规范

每个测试模块应包含:
- `__init__.py` - 模块初始化文件
- `test_*.py` - 测试文件(可以有多个)
- `README.md` - 模块说明文档

## 添加新测试模块

创建新测试模块的步骤:

1. 在 `anp/unittest/` 下创建新目录:
   ```bash
   mkdir anp/unittest/<module_name>
   ```

2. 创建必要文件:
   ```bash
   touch anp/unittest/<module_name>/__init__.py
   touch anp/unittest/<module_name>/test_<feature>.py
   touch anp/unittest/<module_name>/README.md
   ```

3. 在 `test_<feature>.py` 中编写测试:
   ```python
   import unittest

   class TestFeature(unittest.TestCase):
       """测试功能描述"""

       def test_specific_behavior(self):
           """测试具体行为"""
           # 测试代码
           self.assertTrue(result)
   ```

4. 更新本 README,添加新模块说明

## 推荐的测试模块

可以继续添加以下测试模块:

- `encryption/` - 端到端加密测试
- `meta_protocol/` - 元协议协商测试
- `anp_crawler/` - ANP爬虫测试
- `fastanp/` - FastANP框架测试
- `ap2/` - AP2支付协议测试

## 运行特定模式测试

```bash
# 运行包含特定关键字的测试
uv run pytest anp/unittest/ -k "version"

# 运行失败的测试
uv run pytest anp/unittest/ --lf

# 运行最慢的10个测试
uv run pytest anp/unittest/ --durations=10

# 并行运行测试(需要安装 pytest-xdist)
uv run pytest anp/unittest/ -n auto
```

## 持续集成

测试应该:
- 在 CI/CD 流程中自动运行
- 代码提交前本地运行
- Pull Request 时必须通过

## 相关文档

- [测试总结](TESTING_SUMMARY.md) - 详细的测试统计和结果
- [身份认证测试](authentication/README.md) - 身份认证测试详情

## 注意事项

1. 测试代码放在 `anp/unittest/` 目录下
2. 测试文件以 `test_` 开头
3. 测试类继承 `unittest.TestCase`
4. 测试方法以 `test_` 开头
5. 使用 Google Python 编程规范
6. 不要在测试中使用 mock(除非绝对必要)
7. 确保测试可以重复运行
8. 保持测试简单和可读
