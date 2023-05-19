import sys
import unittest

import main

import json

# All the rules that yara matched when ran from terminal
expected = ["SEH_Init", "win_registry", "win_files_operation", "Str_Win32_Winsock2_Library", "CRC32_poly_Constant",
			"CRC32_table", "RijnDael_AES", "RijnDael_AES_CHAR", "WannaDecryptor",
			"Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549", "ransom_telefonica", "Wanna_Cry_Ransomware_Generic",
			"WannaCry_Ransomware", "WannaCry_Ransomware_Dropper", "wannacry_static_ransom", "IsPE32", "IsWindowsGUI",
			"IsPacked", "HasRichSignature", "Microsoft_Visual_Cpp_v60", "Microsoft_Visual_Cpp_v50v60_MFC_additional",
			"Microsoft_Visual_Cpp_50", "Microsoft_Visual_Cpp_v50v60_MFC", "Microsoft_Visual_Cpp"]


# TODO work on testing, and also is it really necessary
class YaraTestCase(unittest.TestCase):
	def test_wannacry(self):
		try:
			res = main.yara_analysis("test/samples/wannacry.exe")
			json.dump(res, sys.stdout, indent=4)
		# self.assertEqual(len(res), len(expected))
		# for i in range(0, len(res)):
		# 	self.assertEqual(res[i], expected[i])
		except Exception as e:
			print(e)
			self.fail("Exception occurred")


if __name__ == '__main__':
	unittest.main()
