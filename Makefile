run:
	python3 client.py
install:
	pip3 install --user --pre scapy[basic]
clean:
	rm -r __pycache__
	rm -r .ipynb_checkpoints