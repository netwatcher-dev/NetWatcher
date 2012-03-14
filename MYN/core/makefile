.SILENT:

REP=.
STRUCTLIB=$(REP)/structlib
SEGMENTLIB=$(REP)/segmentlib
CONTROLLIB=$(REP)/controllib
COLLECTORLIB=$(REP)/collectorlib
UTILLIB=$(REP)/utillib
CAPTUREFILTERLIB=$(REP)/capturefilterlib
SHAREDMEMORYLIB=$(REP)/sharedmemorylib
DELAYEDLIB=$(REP)/delayedlib

CC=gcc -g -O0 -DDEBUG_MEMORY_SEG
EXEC=dispatch start_core control collector command wait filter_test
OBJS=$(DELAYEDLIB)/delayedlib.o $(STRUCTLIB)/structlib.o $(SEGMENTLIB)/segmentlib.o $(CONTROLLIB)/controllib.o $(COLLECTORLIB)/collectorlib.o $(UTILLIB)/utillib.o $(CAPTUREFILTERLIB)/capturefilterlib.o $(SHAREDMEMORYLIB)/sharedmemorylib.o

all: $(EXEC)

$(DELAYEDLIB)/delayedlib.o: $(DELAYEDLIB)/delayedlib.c $(DELAYEDLIB)/delayedlib.h
	echo "############################# creation de delayedlib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(DELAYEDLIB)/delayedlib.c
	mv delayedlib.o $(DELAYEDLIB)

$(SHAREDMEMORYLIB)/sharedmemorylib.o: $(SHAREDMEMORYLIB)/sharedmemorylib.c $(SHAREDMEMORYLIB)/sharedmemorylib.h
	echo "############################# creation de sharedmemorylib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(SHAREDMEMORYLIB)/sharedmemorylib.c
	mv sharedmemorylib.o $(SHAREDMEMORYLIB)

$(CAPTUREFILTERLIB)/capturefilterlib.o: $(CAPTUREFILTERLIB)/capturefilterlib.c $(CAPTUREFILTERLIB)/capturefilterlib.h
	echo "############################# creation de capturefilterlib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(CAPTUREFILTERLIB)/capturefilterlib.c
	mv capturefilterlib.o $(CAPTUREFILTERLIB)

$(STRUCTLIB)/structlib.o: $(STRUCTLIB)/structlib.c $(STRUCTLIB)/structlib.h
	echo "############################# creation de structlib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(STRUCTLIB)/structlib.c
	mv structlib.o $(STRUCTLIB)

$(SEGMENTLIB)/segmentlib.o: $(SEGMENTLIB)/segmentlib.c $(SEGMENTLIB)/segmentlib.h $(STRUCTLIB)/structlib.h
	echo "############################# creation de segmentlib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(SEGMENTLIB)/segmentlib.c
	mv segmentlib.o $(SEGMENTLIB)

$(CONTROLLIB)/controllib.o: $(CONTROLLIB)/controllib.c $(CONTROLLIB)/controllib.h $(UTILLIB)/utillib.o 	$(SHAREDMEMORYLIB)/sharedmemorylib.o
	echo "############################# creation de controllib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(CONTROLLIB)/controllib.c
	mv controllib.o $(CONTROLLIB)

$(COLLECTORLIB)/collectorlib.o: $(COLLECTORLIB)/collectorlib.c $(COLLECTORLIB)/collectorlib.h
	echo "############################# creation de collectorlib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(COLLECTORLIB)/collectorlib.c
	mv collectorlib.o $(COLLECTORLIB)

$(UTILLIB)/utillib.o: $(UTILLIB)/utillib.c $(UTILLIB)/utillib.h
	echo "############################# creation de utillib... #############################"
	$(CC) -ansi -Wall -pedantic -c $(UTILLIB)/utillib.c
	mv utillib.o $(UTILLIB)

dispatch: dispatch.c $(STRUCTLIB)/structlib.o $(SEGMENTLIB)/segmentlib.o $(CAPTUREFILTERLIB)/capturefilterlib.o $(SHAREDMEMORYLIB)/sharedmemorylib.o
	echo "############################# compilation de dispatch... #############################"
	$(CC) -ansi -Wall -pedantic -o dispatch dispatch.c -lpcap $(STRUCTLIB)/structlib.o $(SEGMENTLIB)/segmentlib.o $(CAPTUREFILTERLIB)/capturefilterlib.o $(SHAREDMEMORYLIB)/sharedmemorylib.o

control: control.c $(CONTROLLIB)/controllib.o $(COLLECTORLIB)/collectorlib.o command.h $(UTILLIB)/utillib.o $(SHAREDMEMORYLIB)/sharedmemorylib.o
	echo "############################# compilation de control... #############################"
	$(CC) -ansi -Wall -pedantic -o control control.c $(CONTROLLIB)/controllib.o -lpcap $(COLLECTORLIB)/collectorlib.o $(UTILLIB)/utillib.o $(SHAREDMEMORYLIB)/sharedmemorylib.o

collector: collector.c $(COLLECTORLIB)/collectorlib.o
	echo "############################# compilation de collector... #############################"
	$(CC) -ansi -Wall -pedantic -o collector collector.c $(COLLECTORLIB)/collectorlib.o

start_core: core.c
	echo "############################# compilation de start_core... #############################"
	$(CC) -ansi -Wall -pedantic -lpcap -o start_core core.c

command: command.c command.h $(UTILLIB)/utillib.o
	echo "############################# compilation de command... #############################"
	$(CC) -ansi -Wall -pedantic -o command command.c -lreadline $(UTILLIB)/utillib.o

wait: wait.c
	echo "############################# compilation de wait... #############################"
	$(CC) -ansi -Wall -pedantic -o wait wait.c

filter_test: filter_test.c
	echo "############################# compilation de filter test... #############################"
	$(CC) -ansi -Wall -pedantic -o filter_test filter_test.c

clean:
	@rm -f $(OBJS) core

clobber: clean
	rm -rf $(EXEC)
