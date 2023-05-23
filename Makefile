setup: update_gitmodules setup_virtualenv setup_yara

update_gitmodules:
	git submodule update --init --recursive;

setup_yara:
	sed -i '/include ".\/malware\/MALW_AZORULT.yar"/d' rules/malware_index.yar;

setup_virtualenv:
	virtualenv venv
	source venv/bin/activate && \
	pip install -r requirements.txt