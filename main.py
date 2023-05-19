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
import hashlib
import json
import os
import pathlib
import sys

import pefile
import vt
import yara


def main():
	# Define the command line arguments
	parser = argparse.ArgumentParser(description="Python Executable Analyser (PEA)")
	parser.add_argument("executable", type=argparse.FileType("rb"), help="The executable to be analysed")
	parser.add_argument("--yara", "-y", action="store_true", dest="yara")
	parser.add_argument("--virustotal", "-t", metavar="api_key", default="", dest="virustotal",
						help="Specify to search VirusTotal for the hash of the file. Provide an API key as the option arg")
	parser.add_argument("--metadata", "-m", action="store_true", dest="metadata")
	# parser.add_argument("--disassembly", "-d", action="store_true") # Need to specify a specific function to disassemble
	parser.add_argument("--capa", "-c", action="store_true", dest="capa")
	parser.add_argument("--all", "-a", action="store_true", dest="all")

	# Parse the args into the args variable
	args = parser.parse_args()

	# Call the do_analysis function, passing the arguments as parameters, for the bools passing true if --all was specified even if they weren't
	res = do_analysis(args.executable, args.yara or args.all, args.virustotal,
					  args.metadata or args.all,
					  args.capa or args.all)

	# Print the data as JSON for easy parsing with other tools and close the executable file
	json.dump(res, sys.stdout, indent=4)
	print()
	args.executable.close()


def do_analysis(open_exe_file, do_yara, vt_key, do_metadata, do_capa) -> list:
	exe_path = pathlib.Path(open_exe_file.name).absolute()

	# Save the current directory into a variable and then cd to the project directory for access to the cloned yara rules repository
	cwd = pathlib.Path.cwd()
	project_dir = pathlib.Path(__file__).resolve().parent
	os.chdir(project_dir)

	# Empty array for collecting results
	ret = []

	# Calculate the md5 hash of the file. This is useful for VirusTotal currently might be useful otherwise
	exe_hash = hashlib.md5(open_exe_file.read()).hexdigest()
	open_exe_file.seek(0)

	# For each analysis, if the parameters are set to perform them, then perform them, adding their output into ret
	if do_yara:
		ret.append(yara_analysis(exe_path))
	if len(vt_key) != 0:
		ret.append(virustotal_analysis(exe_hash, vt_key))
	if do_metadata:
		ret.append(metadata_analysis(open_exe_file))
	if do_capa:
		capa_analysis(exe_path)

	# cd back to the saved path
	os.chdir(cwd)

	return ret


def yara_analysis(exe_path) -> dict:
	# Compile the YARA rules files into the appropriate variables
	os.chdir("rules")
	packer_rules: yara.Rules = yara.compile("packers_index.yar")
	malware_rules: yara.Rules = yara.compile("malware_index.yar")
	cve_rules: yara.Rules = yara.compile("cve_rules_index.yar")
	crypto_rules: yara.Rules = yara.compile("crypto_index.yar")
	antidebugvm_rules: yara.Rules = yara.compile("antidebug_antivm_index.yar")
	capabilities_rules: yara.Rules = yara.compile("capabilities_index.yar")
	os.chdir("..")

	# Match the rules against the target file
	packer_matches: list[yara.Match] = packer_rules.match(str(exe_path))
	malware_matches: list[yara.Match] = malware_rules.match(str(exe_path))
	cve_matches: list[yara.Match] = cve_rules.match(str(exe_path))
	crypto_matches: list[yara.Match] = crypto_rules.match(str(exe_path))
	antidebugvm_matches: list[yara.Match] = antidebugvm_rules.match(str(exe_path))
	capabilities_matches: list[yara.Match] = capabilities_rules.match(str(exe_path))

	# Collect the necessary information from the matches - the names of the matched rules
	packer_strs = [str(m.rule) for m in packer_matches]
	malware_strs = [str(m.rule) for m in malware_matches]
	cve_strs = [str(m.rule) for m in cve_matches]
	crypto_strs = [str(m.rule) for m in crypto_matches]
	antidebugvm_strs = [str(m.rule) for m in antidebugvm_matches]
	capabilities_strs = [str(m.rule) for m in capabilities_matches]

	# Declare a data structure to return
	ret = {
		"analysis": "YARA",
		"results": {
			"packers": packer_strs,
			"malware": malware_strs,
			"cve": cve_strs,
			"crypto_strs": crypto_strs,
			"antidebug/vm": antidebugvm_strs,
			"capabilities": capabilities_strs
		}
	}
	return ret


def virustotal_analysis(exe_hash, api_key) -> dict:
	# Pretty simple usage of vt-py here to get information on the file hash
	vt_client = vt.Client(api_key)
	vt_file = vt_client.get_object(f"/files/{exe_hash}")
	vt_client.close()

	# Create a data structure to return, using .get(...) cause if the key doesn't exist that returns null instead of throwing an exception
	ret = {
		"analysis": "VirusTotal",
		"results": {
			"sha256": vt_file.get("sha256"),
			"votes": vt_file.get("total_votes"),
			"file_names": vt_file.get("names"),
			"analysis_stats": vt_file.get("last_analysis_stats"),
			"tags": vt_file.get("tags")
		}
	}
	return ret


def metadata_analysis(open_exe_file):
	pe_signature = b"MZ"
	elf_signature = b"\x7fELF"

	# Read the first 4 bytes of the file
	first_4_bytes = open_exe_file.read(4)
	open_exe_file.seek(0)

	# Check if the first 2 bytes of the file match the PE signature/magic number/header and if not check if the first 4 match the ELF signature
	if first_4_bytes[0:2] == pe_signature:
		# Use pefile to parse the PE metadata
		pe = pefile.PE(data=open_exe_file.read())
		open_exe_file.seek(0)

		# Collect all the imports into an array of objects/dicts that contain the DLL name and a list of imported functions
		imports = [
			{entry.dll.decode("utf-8"): [imp.name.decode("utf-8") for imp in entry.imports]} for entry in
			pe.DIRECTORY_ENTRY_IMPORT
		]

		# It's possible for a file to have no exports e.g. most EXEs
		if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
			# But if it does, collect the exported function names into a list
			exports = [
				entry.name.decode("utf-8") for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols
			]
		else:
			exports = []

		# Build data structure to return
		ret = {
			"analysis": "Metadata",
			"results": {
				"type": "EXE" if pe.is_exe() else "DLL" if pe.is_dll() else "Unknown",
				"imports": imports,
				"exports": exports
			}
		}
		return ret
	elif first_4_bytes == elf_signature:
		# TODO elf
		ret = {
			"analysis": "Metadata",
			"results": {
			}
		}
		return ret
	else:
		# If the first 2/4 bytes do not match that of PE/ELF then print to stderr and return an empty result data structure
		print("[WARN]: File is not a PE or ELF format file", sys.stderr)
		ret = {
			"analysis": "Metadata",
			"results": {
			}
		}
		return ret


def capa_analysis(exe_path):
	pass


# The entry point - just call the defined main function
if __name__ == '__main__':
	main()
