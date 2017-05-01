CC=gcc
CFLAGS= -Ismall_tables/ -Iscalable_tables/ -I/linear_search_tables/ -I ./ -Wall -Wshadow -O0 -g -gdwarf-2 
all: clean scalable_tables small_tables

clean:
	rm -f scalable_tables/*.o scalable_tables/*.gch small_tables/*.o small_tables/*.gch *.o *.gch *.out linear_search_tables/*.o linear_search_tables/*.gch

scalable_tables: scalable_tables.o utility.o
	$(CC) $(CFLAGS) -o scalable_tables.out scalable_tables.o utility.o

scalable_tables.o: scalable_tables/scalable_tables.c scalable_tables/scalable_tables.h utility.c utility.h
	$(CC) $(CFLAGS) -c scalable_tables/scalable_tables.c utility.h

small_tables: small_tables.o utility.o
	$(CC) $(CFLAGS) -o small_tables.out small_tables.o utility.o

small_tables.o: small_tables/small_tables.c small_tables/small_tables.h utility.c utility.h
	$(CC) $(CFLAGS) -c small_tables/small_tables.c utility.h

utility.o: utility.h utility.c
	$(CC) $(CFLAGS) -c utility.c utility.h

linear_search_tables: linear_search_tables.o utility.o
	$(CC) $(CFLAGS) -o linear_search_tables.out linear_search_tables.o utility.o

linear_search_tables.o: linear_search_tables/linear_search_tables.c linear_search_tables/linear_search_tables.h utility.c utility.h
	$(CC) $(CFLAGS) -c linear_search_tables/linear_search_tables.c utility.h

%.run: $*
	@echo -e "\nSTARTING SHORT PREFIX SMALL\n"
	./$*.out ../outputs/shorter_prefix/small_test ../outputs/shorter_prefix/small_test_trace
	@echo -e "\nSTARTING SHORT PREFIX LARGE\n"
	./$*.out ../outputs/shorter_prefix/large_test ../outputs/shorter_prefix/large_test_trace
	@echo -e "\nSTARTING LONG PREFIX SMALL\n"
	./$*.out ../outputs/longer_prefix/small_test ../outputs/longer_prefix/small_test_trace
	@echo -e "\nSTARTING LONG PREFIX LARGE\n"
	./$*.out ../outputs/longer_prefix/large_test ../outputs/longer_prefix/large_test_trace
	@echo -e "\nSTARTING LARGE SET\n"
	./$*.out ../outputs/example ../outputs/example_trace
	@echo -e "\nTESTING COMPLETED..."

%.runtest: $*
	./$*.out ../outputs/test ../outputs/example_trace
