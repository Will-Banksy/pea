# pea

An automated static malware analysis tool that runs various types of analysis on a given file, of which most analysis
works on many formats.
Supported:

- YARA - matches appropriate yara rules against the file, using rules from the
  [yara rules](https://github.com/Yara-Rules/rules/tree/0f93570194a80d2f2032869055808b0ddcdfb360) repository
- VirusTotal - calculates the md5 hash of the executable and looks it up on VirusTotal. Requires a VirusTotal API key
- Metadata - If the file is either a PE or ELF format executable/library, then this will report on the file metadata
- Capabilities - Uses [capa](https://github.com/mandiant/capa) to enumerate the capabilities of the file
- Strings - Extracts ASCII-compatible strings from the file (assuming it's a binary file. If it's a text file there's
  not much point)

## Usage

May require a Linux environment - steps may be different in a windows environment. Untested.

Requires `virtualenv`, `make` and `git` for setup:

```bash
make
```

Once setup is complete, to run the program simply run the bash script `pea`, e.g.:

```bash
./pea -h
```
