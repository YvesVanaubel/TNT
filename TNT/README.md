TNT - Revealing MPLS Tunnels
============================

`TNT` (Trace the Naughty Tunnels) [1,2] is an extension to Paris traceroute for
revealing most (if not all) hidden MPLS tunnels along a path.
It has been implemented within scamper [3], a tool designed to actively probe
destinations in the Internet in parallel.
`TNT` works in two steps: (i) along with traceroute probes, it identifies
evidence of a potential tunnel presence and, (ii), launches additional
dedicated probing to reveal the content of the tunnel, if required.

This README explains how to install and use `TNT`.




Installation
------------------

`TNT` is a scamper driver. It is available in the `scamper` release provided with
this README file (*scamper-tnt-cvs-20180523a*). `scamper` should compile and run
under FreeBSD, OpenBSD, NetBSD, Linux, MacOS X, Solaris, Windows, and DragonFly.
In order to build and install scamper and `TNT`, go to the scamper directory
and type:

```
> ./configure
> make
> make install
```
If needed, more details about the installation of scamper can be found in the
INSTALL file.

Note that the code of `TNT` is located in the following directory:

*scamper-tnt-cvs-20180523a/utils/sc_tnt*




Usage
------------------

`TNT` has two running modes: *measurement* and *dump*.

1. MEASUREMENT

The measurement mode allows to collect traces based on a set of destinations.
It requires a scamper daemon to be running on the monitor:

```
> sudo scamper -D -P portnb
```
This command runs a scamper daemon listening on port portnb.
Once a scamper deamon is running, `TNT` can control this daemon to detect MPLS
tunnels on the paths to a set of destinations:
```
sc_tnt [-?Db] [-a addressfile] [-c pingcount]
       [-f frplathresh] [-i dst] [-l logfile]
       [-m method] [-o outputfile] [-p port]
       [-r rtlathresh] [-s startttl ] [-U unix]

-? give an overview of the usage of sc_tnt
-D start as daemon
-b brute force (try tunnel revelation, even if none of the triggers is positive)
-a input address file, if multiple destinations
-c number of pings for fingerprinting [4]. Default 1
-f threshold value for FRPLA trigger (>0). Default 3
-i destination IP address, if unique destination
-l log file (stores TNT progress)
-m method to collect traces (icmp-paris or udp-paris). Default icmp-paris
-o output warts file
-p port to find scamper on
-r threshold value for RTLA trigger (>0). Default 1
-s start TTL for the initial trace (>0). Default 1
-U unix domain to find scamper on
```
For more information about the different options, please refer to `TNT` paper.

Remarks:
  - `TNT` stores the data in a warts file (binary format used by scamper).
  - *l* and *U* otpions are optional


2. DUMP

The dump mode allows `TNT` to read the content of a warts file and write its
content on the standard output in a human-readable text format:
```
sc_tnt [-v] [-d dump] file.warts

-v verbose display (shows tunnel discovery attempts)
-d dump. Use 1 to display MPLS tunnels
```

A man page explaining the usage of `TNT` is also available with the code.




Dump format
------------------

A standard trace run by scamper has the following output text format:
```
traceroute from 143.129.80.134 to 212.219.171.138
1  143.129.80.190  0.266 ms
2  143.129.67.252  0.528 ms
3  192.168.141.40  1.542 ms
4  192.168.148.101  8.399 ms
5  193.191.18.9  1.024 ms
6  *
7  62.40.124.161  2.677 ms
8  62.40.112.69  7.167 ms
9  62.40.124.198  7.287 ms
10  146.97.33.2  7.730 ms
11  146.97.33.6  8.160 ms
12  146.97.41.86  9.731 ms
13  212.219.171.138  11.008 ms
```

The corresponding `TNT` output is the following:
```
trace [icmp-paris] from 143.129.80.134 to 212.219.171.138
1 143.129.80.190  0.255 ms rTTLs=<64,64> qttl=1
2 143.129.67.252  5.804 ms rTTLs=<254,254> qttl=1
3 192.168.141.40  1.250 ms rsvd rTTLs=<62,*> qttl=1
4 192.168.148.101 16.189 ms rsvd rTTLs=<252,*> qttl=1
5 193.191.18.9    1.600 ms rTTLs=<251,60> qttl=1
6 *
7 62.40.124.161   3.342 ms rTTLs=<248,58> qttl=1 uturn=1 frpla=1 rtla=1
8 62.40.112.69    7.959 ms rTTLs=<248,57> qttl=1
9 62.40.124.198   8.006 ms rTTLs=<247,56> qttl=1
10 146.97.33.2     8.340 ms rTTLs=<246,55> qttl=1
11 146.97.33.6     9.092 ms rTTLs=<245,54> qttl=1
12 146.97.41.86    10.451 ms rTTLs=<244,244> qttl=1
13 212.219.171.138 10.885 ms rTTLs=<243,243>
```
With `TNT`, more information is displayed for each hop:
  * the protocol used for the trace, here Paris traceroute with ICMP probes,
    written as *icmp-paris*.
  * the IP TTLs obtained from the time-exceeded (TE) and the echo-reply (ER)
    messages, written as *rTTLs=<TTL_TE,TTL_ER>*. For the third hop, the TTL
    received due to the traceroute probe is 62, while the node did not respond
    to the ping request (*).
  * the IP TTL value of the traceroute probe quoted in the ICMP TE message sent
    by the hop. It equals 1 (*qttl=1*) for each hop in this trace.
  * the computed uturn value, if different from 0. For hop 7, it is equal to 1,
    and is written as *uturn=1*.
  * the computed frpla and rtla values, if greater than 0. For hop 7, they equal
    both 1, and are written respectively as *frpla=1* and *rtla=1*.
  * the *rsvd* flag if the IP address is a reserved IP address (as defined by
    IETF and IANA). It can be observed at hops 3 and 4.

The previous trace did not cross any MPLS tunnel between the source and the
destination. However, RTLA was positive at hop 7, and a revelation attempt was
tried. This information can be displayed using the verbose mode (*-v* option)
when dumping the warts file:
```
trace [icmp-paris] from 143.129.80.134 to 212.219.171.138
1 143.129.80.190  0.255 ms rTTLs=<64,64> qttl=1
2 143.129.67.252  5.804 ms rTTLs=<254,254> qttl=1
3 192.168.141.40  1.250 ms rsvd rTTLs=<62,*> qttl=1
4 192.168.148.101 16.189 ms rsvd rTTLs=<252,*> qttl=1
5 193.191.18.9    1.600 ms rTTLs=<251,60> qttl=1
6 *
7 62.40.124.161   3.342 ms rTTLs=<248,58> qttl=1 uturn=1 frpla=1 rtla=1 (ATTEMPT,RTLA,NTH-RV)
8 62.40.112.69    7.959 ms rTTLs=<248,57> qttl=1
9 62.40.124.198   8.006 ms rTTLs=<247,56> qttl=1
10 146.97.33.2     8.340 ms rTTLs=<246,55> qttl=1
11 146.97.33.6     9.092 ms rTTLs=<245,54> qttl=1
12 146.97.41.86    10.451 ms rTTLs=<244,244> qttl=1
13 212.219.171.138 10.885 ms rTTLs=<243,243>
```
Any attempt is signalled between parentheses with the key ATTEMPT. Additional
information gives the trigger that caused the attempt, in this case RTLA,
and the reason why `TNT` stopped the revelation. The reasons may be:
  * *NTH-RV* if nothing was revealed, meaning `TNT` did not reveal an node, and
    no tunnel is hidden there.
  * *TGT-NR* if the target was not reached, meaning the revelation trace run to
    the hop (62.40.124.161) did not reach its destination
  * *ING-NF* if the ingress was not found. In this trace, `TNT` tries to reveal a
    tunnel between hops 6 and 7, using hop 5 (193.191.18.9) as entry point
    (the ingress, hop 6, does not respond), and hop 7 (62.40.124.161) as exit
    point (potential egress LER). In order to ensure that the revelation trace
    crosses the hidden tunnel, the entry point must appear in its output. When
    *ING-NF* is written in the ATTEMPT, it means that the entry point could not
    be observed in the revelation trace (due to a routing change or an alias
    for example), and the revelation was aborted.
Note that if the *BUD* tag is also written, it means that the buddy technique was
also tried and failed (the stop reason describes then the buddy attempt).

If run in brute force mode, `TNT` tries to reveal a tunnel when possible, even if
none of the triggers is visible. In this case, no trigger is written in the
corresponding attempts:
```
trace [icmp-paris] from 143.129.80.134 to 212.219.171.138
1 143.129.80.190  0.334 ms rTTLs=<64,64> qttl=1
2 143.129.67.252  0.466 ms rTTLs=<254,254> qttl=1 (ATTEMPT,NTH-RV)
3 192.168.141.40  1.340 ms rsvd rTTLs=<62,*> qttl=1
4 192.168.148.101 4.925 ms rsvd rTTLs=<252,*> qttl=1
5 193.191.18.9    1.593 ms rTTLs=<251,60> qttl=1
6 *
7 62.40.124.161   3.308 ms rTTLs=<248,58> qttl=1 uturn=1 frpla=1 rtla=1 (ATTEMPT,RTLA,NTH-RV)
8 62.40.112.69    9.503 ms rTTLs=<248,57> qttl=1 (ATTEMPT,NTH-RV)
9 62.40.124.198   13.669 ms rTTLs=<247,56> qttl=1 (ATTEMPT,NTH-RV)
10 146.97.33.2     8.492 ms rTTLs=<246,55> qttl=1 (ATTEMPT,NTH-RV)
11 146.97.33.6     8.809 ms rTTLs=<245,54> qttl=1 (ATTEMPT,NTH-RV)
12 146.97.41.86    10.448 ms rTTLs=<244,244> qttl=1 (ATTEMPT,NTH-RV)
13 212.219.171.138 10.915 ms rTTLs=<243,243>
```
Note that attempts are never tried if the entry or exit point is a reserved
IP address.

In case of a revelation, the tunnel is displayed in the output:
```
trace [icmp-paris] from 143.129.80.134 to 159.225.150.48
1 143.129.80.190  0.223 ms rTTLs=<64,64> qttl=1
2 143.129.67.252  0.460 ms rTTLs=<254,254> qttl=1
3 192.168.141.40  1.198 ms rsvd rTTLs=<62,*> qttl=1
4 192.168.148.101 10.623 ms rsvd rTTLs=<252,*> qttl=1
5 193.191.18.9    1.662 ms rTTLs=<251,60> qttl=1
6 *
7 77.67.93.181    6.019 ms rTTLs=<244,54> qttl=1 uturn=1 frpla=5 rtla=1 [MPLS,INV,ING,RTLA]
H1 89.149.186.230  16.585 ms rTTLs=<242,53> qttl=1 uturn=2 frpla=6 rtla=2 [MPLS,INV,LSR,RTLA,DPR,step=1]
H2 89.149.132.14   9.679 ms rTTLs=<243,53> qttl=1 uturn=1 frpla=4 rtla=1 [MPLS,INV,LSR,RTLA,DPR,step=1]
H3 89.149.129.62   10.746 ms rTTLs=<245,54> qttl=1 frpla=1 [MPLS,INV,LSR,RTLA,DPR,step=1]
H4 89.149.133.154  9.499 ms rTTLs=<246,55> qttl=1 [MPLS,INV,LSR,RTLA,DPR,step=1]
H5 141.136.111.165 94.969 ms rTTLs=<238,48> qttl=1 uturn=1 frpla=6 rtla=1 [MPLS,INV,LSR,RTLA,DPR,step=1]
8 89.149.142.254  93.569 ms rTTLs=<243,53> qttl=1 uturn=1 frpla=5 rtla=1 [MPLS,INV,EGR,RTLA]
9 192.205.37.193  97.511 ms rTTLs=<242,242> qttl=1 frpla=5 [MPLS,EXP,ING]
10 12.122.134.134  145.976 ms rTTLs=<235,*> qttl=1 frpla=11 [MPLS,EXP,LSR] Labels 25316 mTTL=1
11 12.122.28.205   169.545 ms rTTLs=<236,*> qttl=2 frpla=9 [MPLS,EXP,LSR] Labels 35698 mTTL=1 | 25874 mTTL=1
12 12.122.28.77    168.679 ms rTTLs=<237,*> qttl=3 frpla=7 [MPLS,EXP,LSR] Labels 35908 mTTL=1 | 25874 mTTL=2
13 12.122.28.46    149.394 ms rTTLs=<238,*> qttl=4 frpla=5 [MPLS,EXP,LSR] Labels 35341 mTTL=1 | 25874 mTTL=3
14 12.122.1.185    149.481 ms rTTLs=<239,*> qttl=5 frpla=3 [MPLS,EXP,LSR] Labels 35465 mTTL=1 | 25874 mTTL=4
15 12.122.2.166    170.206 ms rTTLs=<240,*> qttl=6 frpla=1 [MPLS,EXP,LSR] Labels 0 mTTL=1 | 25874 mTTL=5
16 12.122.154.66   161.711 ms rTTLs=<237,*> qttl=7 frpla=3 [MPLS,EXP,LSR] Labels 0 mTTL=1 | 25265 mTTL=1
17 12.122.154.73   169.567 ms rTTLs=<241,*> qttl=1 [MPLS,EXP,EGR]
18 206.121.1.58    159.143 ms rTTLs=<237,*> qttl=1 frpla=1
19 *
20 *
21 *
22 *
23 *
```
MPLS information is written between square brackets for each router of a tunnel:
  * an *MPLS* tag
  * the type of tunnel it belongs to: *EXP* (explicit), *IMP* (implicit),
    *OPA* (opaque), *INV* (invisible), or *INF* (inferred, i.e. a router between two
    identified MPLS tunnels, and inferred as an LSR)
  * the type of router: *LSR* for an internal node, *ING* for an ingress LER, or
    *EGR* for an egress LER.
  * the trigger or indicator that signalled the presence of the tunnel:
    DUPIP (duplicate IP address), *RTLA*, *FRPLA*, *QTTL*, *UTURN*, *MTTL* (MPLS TTL,
    i.e. LSE TTL), or *BTFC* (no trigger, brute force).
  * the revelation technique used to reveal the node: *DPR*, *BRPR*, *BUDDY* (buddy
    technique), or *UNKN* (i.e. 1HOP_LSP where the distinction between DPR and
    BRPR is impossible).
  * the revelation step at which the LSR was revealed : *step=X*
  * the *INCOMP?* tag: this tag appears at the ingress LER only if the revelation
    had to stop before being sure all the hops were revealed (due to TGT-NR or
    ING-NF).
  * MPLS labels: *Labels toplab mTTL=X | midlab mTTL=Y | botlab mTTL=Z*
    Each label in the stack is separated by |
    The LSE TTLs (mTTL) are also displayed.
    The MPLS labels are written outside the square brackets.

Note that some of the MPLS information do not appear depending on the type of
the tunnel.
The revealed hops have their own indexing starting with H to not alter the
original trace indexing.
In the previous trace, an invisible LSP was revealed between hops 7 and 8.
The LSP contains hops H1 to H5. The revelation technique was DPR, and the
trigger was FRPLA. An explicit tunnel also appears from hop 9 to 17.




Examples
------------------

This section gives a few examples on the usage of `TNT`. We assume that a `scamper`
daemon is listening on port 12345. The traces are written in the output warts
file named *out.warts*.

1. The following command runs a `TNT` trace to the destination 206.121.1.58:
```
> sc_tnt -i 206.121.1.58 -p 12345 -o out.warts
```
2. The following command runs `TNT` traces to a set of destinations written
in the file dst.txt. `TNT` is run as a daemon:
```
> sc_tnt -D -a dst.txt -p 12345 -o out.warts
```
3. The following command runs a `TNT` trace to the destination 206.121.1.58,
in brute force mode, using Paris traceroute in UDP mode:
```
> sc_tnt -i 206.121.1.58 -p 12345 -o out.warts -m udp-paris -b
```
4. The following command runs a `TNT` trace to the destination 206.121.1.58,
setting the FRPLA threshold to 5 and the RTLA threshold to 2:
```
> sc_tnt -i 206.121.1.58 -p 12345 -o out.warts -f 5 -r 2
```
5. The following command runs a `TNT` trace to the destination 206.121.1.58,
starting the trace with a TTL at 4, and logging the progress in the file log.txt
```
> sc_tnt -i 206.121.1.58 -p 12345 -o out.warts -s 4 -l log.txt
```
6. The following command runs a `TNT` trace to the destination 206.121.1.58,
sending 6 pings per IP address:
```
> sc_tnt -i 206.121.1.58 -p 12345 -o out.warts -c 6
```
7. The following command dumps a warts file:
```
> sc_tnt -d1 out.warts
```
8. The following command dumps a warts file in verbose mode:
```
> sc_tnt -vd1 out.warts
```



References
------------------

[1] Y. VANAUBEL, P. MERINDOL, J.-J. PANSIOT, and B. DONNET,
    Through the Wormhole: Tracking Invisible MPLS Tunnels,
    Proceedings of the 2017 Conference on Internet Measurement Conference

[2] Y. VANAUBEL, P. MERINDOL, J.-J. PANSIOT, and B. DONNET,
    TNT, Watch me Explode: A Light in the Dark for Revealing All MPLS Tunnels

[3] M. LUCKIE,
    Scamper: a Scalable and Extensible Packet Prober for Active Measurement of the Internet,
    ACM SIGCOMM Internet Measurement Conference, November 2010.
    See: [https://www.caida.org/tools/measurement/scamper/](https://www.caida.org/tools/measurement/scamper/)

[4] Y. VANAUBEL, J.-J. PANSIOT, P. MERINDOL, and B. DONNET,
    Network fingerprinting: TTL-based router signatures,
    Proceedings of the 2013 Conference on Internet Measurement Conference, 369-376




Authors
------------------

**Implementation**:
Y. VANAUBEL

**Contributors**:
P. MERINDOL
J.-J. PANSIOT
B. DONNET

Contact: [http://www.montefiore.ulg.ac.be/~bdonnet/mpls/contact.html](http://www.montefiore.ulg.ac.be/~bdonnet/mpls/contact.html)


License
------------------

The project is licensed under the GPLv2.
