.PHONY: clean

LOGS    = log_*
TEMPORARY = tmp_*
RESULTS = output/*

clean:
	rm -f $(LOGS)
	rm -f $(TEMPORARY)
	rm -f $(RESULTS)
