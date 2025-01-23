.PHONY: clean

LOGS    = log_*
TEMPORARY = tmp_*
RESULTS = output/*
QUERIES = query_*

clean:
	rm -f $(LOGS)
	rm -f $(TEMPORARY)
	rm -f $(RESULTS)
	rm -f $(QUERIES)