# ZavetSec-MailInspector
NAME := ZavetSec-MailInspector
SRC  := ZavetSec-MailInspector.py

.PHONY: help install run demo pyz exe clean

help:
	@echo "Цели:"
	@echo "  install   установить опциональные зависимости"
	@echo "  demo      прогон на встроенном примере письма"
	@echo "  run F=..  прогон на файле F (напр. make run F=msg.eml)"
	@echo "  pyz       собрать портативный .pyz (дружелюбный к AV)"
	@echo "  exe       собрать однофайловый .exe (PyInstaller)"
	@echo "  clean     удалить артефакты сборки"

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
