# PacketForwarding
Comparison of two IP routing table lookup schemes.

## IP Routing Lookup Schemes

[Small Forwarding Tables for Fast Routing Lookups](http://conferences.sigcomm.org/sigcomm/1997/papers/p192.pdf)

[Scalable High Speed IP Routing Lookups](http://conferences.sigcomm.org/sigcomm/1997/papers/p182.pdf)
  

## Directory Structure

- classbench
  - db\_generator
  - parameter\_files
  - trace\_generator
- source
  - small\_tables
  - scalable\_tables

The classbench directory contains all the code needed to build and run classbench.  
[Classbench](http://www.arl.wustl.edu/classbench/)

The source directory will contain code that is shared between the two schemes
Code specific to each lookup scheme is contained in their respective directories.

## Running Tests

1. Build classbench by running the following in the classbench directory:
```
make all
```

2. Build the routing table tests by running the following in the source directory:
```
make all
```

3. Generate a filter file and a trace file with classbench by running the following in the db\_generator directory:
```
./db_generator -bc ../parameter_files/fw1_seed 10000 2 -0.5 0.1 ../../outputs/fw1_filter_10k
./trace_generator 1 1 10 ../../outputs/fw1_filter_10k
```

4. Run the tests on routing tables in the source directory:
```
./small_tables ../outputs/fw1_filter_10k ../outputs/fw1_filter_10k_trace
./scalable_tables ../outputs/fw1_filter_10k ../outputs/fw1_filter_10k_trace
```
