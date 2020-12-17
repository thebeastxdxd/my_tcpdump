# CC is a standard variable in Makefiles for the compiler used
CC = gcc
# OBJ variable is used to store all of the intermidate OBJs files we want
OBJ = main.o tcpdump.o bpf_pcap.o pcap_file.o
CFLAGS = -lpcap
# add header files as dependencies so that when they are changed we recompile
DEPS = error.h tcpdump.h bpf_pcap.h pcap_file.h

TARGET = my_tcpdump

# PHONY allows me to create a make rule that the rule's target is not actually a file
.PHONY: clean run

# rule for compiling all c files to objs
# the $@ is an automatic variable which is replaced with the target name
# the $< is an automatic variable which is replaced with the first dependencies
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

# rule for our executable
# the $^ is an automatic variable which is replaced with the list of dependencies
$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $^ $(CFLAGS)

# TODO: make this get params?
run: $(TARGET)
	sudo ./$(TARGET)	

clean:
	rm -f $(OBJ) $(TARGET)
