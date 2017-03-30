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

