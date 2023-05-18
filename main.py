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
import os
import pathlib

import yara


def main():
	parser = argparse.ArgumentParser(description="Python Executable Analyser (PEA)")
	parser.add_argument("executable", type=argparse.FileType("r"), help="The executable to be analysed")
	parser.add_argument("--yara", "-y", action="store_true", dest="yara")
	parser.add_argument("--virustotal", "-t", action="store_true", dest="virustotal")
	parser.add_argument("--metadata", "-m", action="store_true", dest="metadata")
	# parser.add_argument("--disassembly", "-d", action="store_true") # Need to specify a specific function to disassemble
	parser.add_argument("--capa", "-c", action="store_true", dest="capa")
	parser.add_argument("--all", "-a", action="store_true", dest="all")
	args = parser.parse_args()

	do_analysis(args.executable, parser.yara or parser.all, parser.virustotal or parser.all,
				parser.metadata or parser.all,
				parser.capa or parser.all)


if __name__ == '__main__':
	main()


def do_analysis(exe_path_rel, do_yara, do_vt, do_metadata, do_capa):
	exe_path = pathlib.Path(exe_path_rel).absolute()

	cwd = pathlib.Path.cwd()
	project_dir = pathlib.Path(__file__).resolve().parent
	os.chdir(project_dir)

	if do_yara:
		yara_analysis(exe_path)
	if do_vt:
		virustotal_analysis(exe_path)
	if do_metadata:
		metadata_analysis(exe_path)
	if do_capa:
		capa_analysis(exe_path)

	os.chdir(cwd)


def yara_analysis(exe_path):
	os.chdir("rules")
	all_rules = yara.compile("index.yar")
	os.chdir("..")
	matches = all_rules.match(exe_path)
	print(matches)


def virustotal_analysis(exe_path):
	pass


def metadata_analysis(exe_path):
	pass


def capa_analysis(exe_path):
	pass
