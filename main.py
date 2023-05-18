# Python Executable Analyser (PEA)
# Capabilities
#     Matching YARA rules (pkg: yara-python)
#     ClamAV scanning (pkg: python-clamav or clamd (https://github.com/graingert/python-clamd))
#     VirusTotal scanning (pkg: vt-py) - VirusTotal I think lists ClamAV results so if I can use VirusTotal that kinda makes ClamAV integration unnecessary
#     Import/Export listing, library listing (pkgs: pyelftools, pefile)
#     Function disassembly (and decompilation?) with perhaps capstone or rizin and decompilation if implemented either though rizin with rz-ghidra or using ghidra directly somehow. Or maybe using retdec or jsdec or another decompiler
#     Capability listing with capa
#     argparse

import argparse


class AnalysisResult:
	def __init__(self):
		pass


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Python Executable Analyser (PEA)")
	parser.add_argument("executable", type=argparse.FileType("r"), help="The executable to be analysed")
	parser.add_argument("--yara", "-y", action="store_true")
	parser.add_argument("--virustotal", "-t", action="store_true")
	parser.add_argument("--metadata", "-m", action="store_true")
	# parser.add_argument("--disassembly", "-d", action="store_true") # Need to specify a specific function to disassemble
	parser.add_argument("--capa", "-c", action="store_true")
	args = parser.parse_args()

	executable_path = args.executable


def yara_analysis():
	pass


def virustotal_analysis():
	pass


def metadata_analysis():
	pass


def capa_analysis():
	pass
