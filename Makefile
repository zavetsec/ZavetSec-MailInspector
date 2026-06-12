# ZavetSec-MailInspector
NAME := ZavetSec-MailInspector
SRC  := ZavetSec-MailInspector.py

.PHONY: help install run demo pyz exe clean

help:
	@echo "Targets:"
	@echo "  install   pip install optional dependencies"
	@echo "  demo      run against the bundled sample e-mail"
	@echo "  run F=..  run against file F (e.g. make run F=msg.eml)"
	@echo "  pyz       build portable single-file .pyz (AV-friendly)"
	@echo "  exe       build single-file .exe (PyInstaller)"
	@echo "  clean     remove build artifacts"

install:
	pip install -r requirements.txt

demo:
	-python3 $(SRC) examples/sample_phish.eml -o demo.html

run:
	-python3 $(SRC) $(F) -o report.html -j result.json

pyz:
	bash build/build.sh pyz

exe:
	bash build/build.sh exe

clean:
	bash build/build.sh clean
	rm -f demo.html report.html result.json
