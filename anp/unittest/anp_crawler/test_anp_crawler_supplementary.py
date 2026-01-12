"""ANP Crawler Supplementary Tests.

This module provides additional unit tests for ANP Crawler functionality:
- Edge cases and error handling
- URL normalization and validation
- Cache functionality
- Document parsing
"""

import unittest

from anp.anp_crawler.anp_parser import ANPDocumentParser


class TestANPDocumentParserEdgeCases(unittest.TestCase):
    """测试 ANPDocumentParser 边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.parser = ANPDocumentParser()

    def test_parse_empty_content(self):
        """测试空内容的处理"""
        result = self.parser.parse_document("", "application/json", "test_url")

        self.assertIn("interfaces", result)
        self.assertEqual(len(result["interfaces"]), 0)

    def test_parse_malformed_json(self):
        """测试格式错误的 JSON"""
        malformed_json = '{"key": "value", invalid}'

        result = self.parser.parse_document(malformed_json, "application/json", "test_url")

        self.assertIn("interfaces", result)
        self.assertEqual(len(result["interfaces"]), 0)

    def test_parse_non_json_content(self):
        """测试非 JSON 内容"""
        text_content = "This is plain text content"

        result = self.parser.parse_document(text_content, "text/plain", "test_url")

        self.assertIn("interfaces", result)
        # 非 JSON 内容应该没有接口
        self.assertEqual(len(result["interfaces"]), 0)

    def test_parse_openrpc_without_methods(self):
        """测试没有 methods 的 OpenRPC 文档"""
        import json
        openrpc_doc = {
            "openrpc": "1.3.2",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            # 缺少 methods 字段
        }

        content = json.dumps(openrpc_doc)
        result = self.parser.parse_document(content, "application/json", "test_url")

        self.assertIn("interfaces", result)
        # 没有 methods 应该返回空列表
        self.assertEqual(len(result["interfaces"]), 0)

    def test_parse_agent_description_without_interfaces(self):
        """测试没有 interfaces 的 Agent Description"""
        import json
        agent_desc = {
            "id": "did:wba:example",
            "type": "AgentDescription",
            "name": "Test Agent",
            "description": "Test description"
            # 缺少 interfaces 字段
        }

        content = json.dumps(agent_desc)
        result = self.parser.parse_document(content, "application/json", "test_url")

        self.assertIn("interfaces", result)
        self.assertEqual(len(result["interfaces"]), 0)

    def test_parse_openrpc_with_empty_methods(self):
        """测试 methods 为空数组的 OpenRPC 文档"""
        import json
        openrpc_doc = {
            "openrpc": "1.3.2",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "methods": []
        }

        content = json.dumps(openrpc_doc)
        result = self.parser.parse_document(content, "application/json", "test_url")

        self.assertIn("interfaces", result)
        self.assertEqual(len(result["interfaces"]), 0)

    def test_parse_valid_openrpc_method(self):
        """测试解析有效的 OpenRPC 方法"""
        import json
        openrpc_doc = {
            "openrpc": "1.3.2",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "methods": [
                {
                    "name": "testMethod",
                    "description": "Test method description",
                    "params": [
                        {
                            "name": "param1",
                            "description": "First parameter",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "result": {
                        "name": "result",
                        "schema": {"type": "object"}
                    }
                }
            ]
        }

        content = json.dumps(openrpc_doc)
        result = self.parser.parse_document(content, "application/json", "test_url")

        self.assertIn("interfaces", result)
        interfaces = result["interfaces"]
        self.assertEqual(len(interfaces), 1)

        # 验证接口结构
        interface = interfaces[0]
        self.assertEqual(interface["type"], "openrpc_method")
        self.assertEqual(interface["protocol"], "openrpc")
        self.assertEqual(interface["method_name"], "testMethod")
        self.assertIn("params", interface)


class TestURLHandling(unittest.TestCase):
    """测试 URL 处理相关功能"""

    def test_url_normalization(self):
        """测试 URL 规范化"""
        from anp.anp_crawler.anp_crawler import ANPCrawler
        from unittest.mock import MagicMock, patch

        with patch('anp.anp_crawler.anp_client.DIDWbaAuthHeader'):
            crawler = ANPCrawler(
                did_document_path="test/did.json",
                private_key_path="test/key.pem"
            )

            # 测试去除 URL 参数
            test_cases = [
                ("https://example.com/path?param=value", "https://example.com/path"),
                ("https://example.com/path?a=1&b=2", "https://example.com/path"),
                ("https://example.com/path#fragment", "https://example.com/path"),
                ("https://example.com/path?param=value#fragment", "https://example.com/path"),
                ("https://example.com/path", "https://example.com/path"),
            ]

            for input_url, expected in test_cases:
                result = crawler._remove_url_params(input_url)
                self.assertEqual(result, expected)


class TestCacheManagement(unittest.TestCase):
    """测试缓存管理功能"""

    def test_cache_disabled_by_default(self):
        """测试缓存默认禁用"""
        from anp.anp_crawler.anp_crawler import ANPCrawler
        from unittest.mock import patch

        with patch('anp.anp_crawler.anp_client.DIDWbaAuthHeader'):
            crawler = ANPCrawler(
                did_document_path="test/did.json",
                private_key_path="test/key.pem",
                cache_enabled=False
            )

            self.assertFalse(crawler.cache_enabled)

    def test_cache_size_tracking(self):
        """测试缓存大小跟踪"""
        from anp.anp_crawler.anp_crawler import ANPCrawler
        from unittest.mock import patch

        with patch('anp.anp_crawler.anp_client.DIDWbaAuthHeader'):
            crawler = ANPCrawler(
                did_document_path="test/did.json",
                private_key_path="test/key.pem",
                cache_enabled=True
            )

            # 初始缓存应该为空
            self.assertEqual(crawler.get_cache_size(), 0)

            # 手动添加缓存项
            crawler._cache["url1"] = {"data": "test1"}
            crawler._cache["url2"] = {"data": "test2"}

            self.assertEqual(crawler.get_cache_size(), 2)

    def test_clear_cache_functionality(self):
        """测试清除缓存功能"""
        from anp.anp_crawler.anp_crawler import ANPCrawler
        from unittest.mock import patch

        with patch('anp.anp_crawler.anp_client.DIDWbaAuthHeader'):
            crawler = ANPCrawler(
                did_document_path="test/did.json",
                private_key_path="test/key.pem",
                cache_enabled=True
            )

            # 添加缓存和访问记录
            crawler._cache["url1"] = {"data": "test"}
            crawler._visited_urls.add("url1")

            self.assertEqual(crawler.get_cache_size(), 1)
            self.assertEqual(len(crawler.get_visited_urls()), 1)

            # 清除缓存
            crawler.clear_cache()

            self.assertEqual(crawler.get_cache_size(), 0)
            self.assertEqual(len(crawler.get_visited_urls()), 0)


if __name__ == "__main__":
    unittest.main()
