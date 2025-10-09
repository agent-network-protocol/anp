#!/usr/bin/env python3
"""
ANP Crawler Test Runner

Simple script to run all tests for the ANP Crawler module.
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from octopus.utils.log_base import setup_enhanced_logging
from test_anp_crawler import TestANPCrawler, TestANPDocumentParser, TestANPInterface


def main():
    """Main test runner function."""
    print("="*60)
    print("ANP Crawler Test Suite")
    print("="*60)
    print("Testing anp_crawler.py and related modules...")
    print()
    
    # Setup logging
    setup_enhanced_logging(level="INFO")
    
    try:
        # Create test loader
        loader = unittest.TestLoader()
        
        # Create test suite
        suite = unittest.TestSuite()
        
        # Add test cases
        suite.addTests(loader.loadTestsFromTestCase(TestANPCrawler))
        suite.addTests(loader.loadTestsFromTestCase(TestANPDocumentParser))
        suite.addTests(loader.loadTestsFromTestCase(TestANPInterface))
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        # Print summary
        print(f"\n{'='*50}")
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        if result.testsRun > 0:
            success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
            print(f"Success rate: {success_rate:.1f}%")
        print(f"{'='*50}")
        
        # Exit with appropriate code
        if result.failures or result.errors:
            print("\n❌ Some tests failed!")
            sys.exit(1)
        else:
            print("\n✅ All tests passed!")
            sys.exit(0)
            
    except Exception as e:
        print(f"\n💥 Error running tests: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()