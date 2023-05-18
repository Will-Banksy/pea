import unittest

import main


class YaraTestCase(unittest.TestCase):
	def test_wannacry(self):
		try:
			main.yara_analysis("test/samples/wannacry.exe")
		except Exception as e:
			print(e)
			self.fail("Exception occurred")


if __name__ == '__main__':
	unittest.main()
