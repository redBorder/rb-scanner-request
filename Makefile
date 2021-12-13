all:   
	$(MAKE) -C src/rb-scanner-request/
	cp src/rb-scanner-request/rb-scanner-request .
install:
	$(MAKE) -c src/rb-scanner-request/ install
clean:
	rm -f rb-scanner-request
	$(MAKE) -C src/rb-scanner-request/ clean
rpm:
	$(MAKE) -C packaging/rpm
