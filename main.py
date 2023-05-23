# Python Executable Analyser (PEA)

import argparse
import hashlib
import json
import operator
import os
import pathlib
import string
import subprocess
import sys
from functools import reduce

import pefile
import vt
import yara

from elftools.elf import elffile


def main():
	default_min_strings = 5

	# Define the command line arguments
	parser = argparse.ArgumentParser(prog="pea", description="Python Executable Analyser (PEA)")
	parser.add_argument("executable", type=argparse.FileType("rb"), help="The executable to be analysed")
	parser.add_argument("--version", "-V", action="version", version="Python Executable Analyser (PEA) v1.0",
						help="Print version and exit")
	parser.add_argument("--yara", "-y", action="store_true", dest="yara",
						help="Perform YARA rule matching")
	parser.add_argument("--virustotal", "-t", metavar="api_key", default="", dest="virustotal",
						help="Search VirusTotal for the hash of the file. Provide an API key as the option argument")
	parser.add_argument("--metadata", "-m", action="store_true", dest="metadata",
						help="Read the executable metadata")
	# parser.add_argument("--disassembly", "-d", action="store_true") # Need to specify a specific function to disassemble
	parser.add_argument("--capa", "-c", action="store_true", dest="capa",
						help="Perform capabilities analysis using flare-capa")
	parser.add_argument("--strings", "-s", metavar="min_chars", type=int, const=default_min_strings, default=-1,
						nargs="?",
						dest="strings",
						help="Extract ASCII-compatible strings. Provide the minimum string length as the option argument, will default to 5 if omitted. May produce a lot of output especially at lower minimum string lengths")
	parser.add_argument("--all", "-a", action="store_true", dest="all",
						help="Perform yara, metadata, capa and strings analysis")

	# Parse the args into the args variable
	args = parser.parse_args()

	# Call the do_analysis function, passing the arguments as parameters, for the bools passing true if --all was specified even if they weren't
	res = do_analysis(args.executable,
					  args.yara or args.all,
					  len(args.virustotal) != 0,
					  args.metadata or args.all,
					  args.capa or args.all,
					  args.strings != -1 or args.all,
					  args.virustotal,
					  args.strings if args.strings != -1 else default_min_strings)

	# Print the data as JSON for easy parsing with other tools and close the executable file
	json.dump(res, sys.stdout, indent=4)
	print()
	args.executable.close()


def do_analysis(open_exe_file, do_yara, do_virustotal, do_metadata, do_capa, do_strings, vt_api_key,
				strings_len) -> list:
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
		print("[INFO] Matching YARA rules...", file=sys.stderr)
		ret.append(yara_analysis(exe_path))
	if do_virustotal and len(vt_api_key) != 0:
		print("[INFO] Looking up executable on VirusTotal...", file=sys.stderr)
		ret.append(virustotal_analysis(exe_hash, vt_api_key))
	if do_metadata:
		print("[INFO] Examining executable metadata...", file=sys.stderr)
		ret.append(metadata_analysis(open_exe_file))
	if do_capa:
		print("[INFO] Performing capabilities analysis...", file=sys.stderr)
		ret.append(capa_analysis(exe_path))
	if do_strings:
		print("[INFO] Extracting strings...", file=sys.stderr)
		ret.append(strings_analysis(open_exe_file, strings_len))

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
	return {
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


def virustotal_analysis(exe_hash, api_key) -> dict:
	# Pretty simple usage of vt-py here to get information on the file hash
	vt_client = vt.Client(api_key)
	vt_file = vt_client.get_object(f"/files/{exe_hash}")
	vt_client.close()

	# Create a data structure to return, using .get(...) cause if the key doesn't exist that returns null instead of throwing an exception
	return {
		"analysis": "VirusTotal",
		"results": {
			"sha256": vt_file.get("sha256"),
			"votes": vt_file.get("total_votes"),
			"file_names": vt_file.get("names"),
			"analysis_stats": vt_file.get("last_analysis_stats"),
			"tags": vt_file.get("tags")
		}
	}


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

		# Collect necessary information from the PE sections
		sections = [{
			"name": sect.Name.decode("utf-8").rstrip("\x00"),
			"size": hex(sect.SizeOfRawData),
			"virtual_size": hex(sect.Misc_VirtualSize),
		} for sect in pe.sections]

		# Build data structure to return
		return {
			"analysis": "metadata",
			"results": {
				"format": "PE",
				"type": "EXE" if pe.is_exe() else "DLL" if pe.is_dll() else "driver" if pe.is_driver() else "Unknown",
				"machine_type": "x86" if pe.FILE_HEADER.Machine == 0x14c else "x86_64" if pe.FILE_HEADER.Machine == 0x8664 else pe.FILE_HEADER.Machine,
				"subsystem": "gui" if pe.OPTIONAL_HEADER.Subsystem == 2 else "cui" if pe.OPTIONAL_HEADER.Subsystem == 3 else pe.OPTIONAL_HEADER.Subsystem,
				"imports": imports,
				"exports": exports,
				"sections": sections
			}
		}
	elif first_4_bytes == elf_signature:
		# Init elf file object form fstream
		elf = elffile.ELFFile(stream=open_exe_file)

		# Collect section information
		sections = [{
			"name": sect.name,
			"type": sect.header.sh_type
		} for sect in elf.iter_sections()]

		symbol_tables = [symtabs for symtabs in elf.iter_sections() if isinstance(symtabs, elffile.SymbolTableSection)]

		symbols = reduce(operator.iconcat, [sect.iter_symbols() for sect in symbol_tables], [])
		symbols_strs = [sym.name for sym in symbols]

		# Build data structure to return
		return {
			"analysis": "metadata",
			"results": {
				"format": "ELF",
				"type": "executable" if elf.header.e_type == "ET_EXEC" else "shared object" if elf.header.e_type == "ET_DYN" else "relocatable" if elf.header.e_type == "ET_REL" else "Core" if elf.header.e_type == "ET_CORE" else elf.header.e_type,
				"class": f"{elf.elfclass}-bit",
				"machine": "x86_64" if elf.header.e_machine == "EM_X86_64" else "x86" if elf.header.e_machine == "EM_386" else elf.header.e_machine,
				"has_debug_info": elf.has_dwarf_info(),
				"sections": sections,
				"symbols": symbols_strs
			}
		}
	else:
		# If the first 2/4 bytes do not match that of PE/ELF then print to stderr and return an empty result data structure
		print("[ERROR]: Metadata analysis failed: File is not a PE or ELF format file", file=sys.stderr)
		return {
			"analysis": "metadata",
			"results": {
			}
		}


def capa_analysis(exe_path):
	# Start the capa process and await it finishing, capturing stdout
	proc = subprocess.Popen(["capa", "-r", "capa/rules", "-s", "capa/sigs", "--color", "never", exe_path],
							stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, _ = proc.communicate()
	capa_out = stdout.decode("utf-8").strip()

	collector = []

	# Parse capa output
	# Find capability table
	capability_idx = capa_out.rfind("CAPABILITY")
	# End of line index
	eol_idx = capa_out.find("\n", capability_idx)
	while True:
		# Advance the end of line index to the next line and if another newline character is not found or the "+" character (indicating end of table) is found then break
		eol_idx = capa_out.find("\n", eol_idx + 1)
		if eol_idx == -1 or capa_out[eol_idx + 1] == "+":
			break

		# Find end of cell and end of rule indexes (if a double space is not found then the rule probably goes until the cell end so account for that)
		eoc_idx = capa_out.find("|", eol_idx + 3)
		eor_idx = capa_out.find("  ", eol_idx + 3, eoc_idx)
		if eor_idx == -1:
			eor_idx = eoc_idx - 2

		# Extract the rule name which for some reason has some weird characters before and after it so remove those
		rulename = capa_out[(eol_idx + 3):eor_idx].replace("\u001b[0m", "")
		collector.append(rulename)

	# Build data structure to return
	return {
		"analysis": "capa",
		"results": {
			"capabilities": collector
		}
	}


def strings_analysis(open_exe_file, strings_len):
	# A set of all printable ascii characters in numeric form to be able to be compared with bytes (which are just integers)
	printable = {ord(c) for c in string.printable}

	# Variables to hold state while searching
	curr_barray = bytearray()
	strs = []

	# Iterate through each byte in the file and check whether it exists in the printable set
	# Worth mentioning that this only supports ASCII-compatible strings such as ASCII-compatible UTF-8
	for b in open_exe_file.read():
		if b in printable:
			# If so then add it to the byte array that is currently being constructed
			curr_barray.append(b)
		else:
			# Otherwise if the current byte array is of length greater than the specified minimum then add it to the found list of strings and either way clear the current byte array
			if len(curr_barray) > strings_len:
				strs.append(curr_barray.decode("ascii"))
			curr_barray.clear()

	# Build a data structure to return
	return {
		"analysis": "strings",
		"results": {
			"strings": strs
		}
	}


# The entry point - just call the defined main function
if __name__ == '__main__':
	main()
