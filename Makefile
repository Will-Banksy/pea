setup: setup_virtualenv setup_yara

setup_yara:
	git submodule update --recursive;
	sed -i '/include ".\/malware\/MALW_AZORULT.yar"/d' rules/malware_index.yar;

setup_virtualenv:
	virtualenv venv
	source venv/bin/activate && \
	pip install -r requirements.txt