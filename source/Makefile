CC=gcc
CFLAGS= -Ismall_tables/ -Iscalable_tables/ -I ./ -Wall -Wshadow -O0 -g -gdwarf-2 
all: clean scalable_tables small_tables

clean:
	rm scalable_tables/*.o scalable_tables/*.gch rm small_tables/*.o rm small_tables/*.gch rm *.o rm *.gch *.out

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


