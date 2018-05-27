TNT - Revealing MPLS Tunnels
============================

`TNT` (Trace the Naughty Tunnels) [1,2] is an extension to Paris traceroute for
revealing most (if not all) hidden MPLS tunnels along a path.
It has been implemented within scamper [3], a tool designed to actively probe
destinations in the Internet in parallel.
`TNT` works in two steps: (i) along with traceroute probes, it identifies
evidence of a potential tunnel presence and, (ii), launches additional
dedicated probing to reveal the content of the tunnel, if required.




Content
------------------

The directory *TNT/* contains the implementation of `TNT`.

The directory *Python/* contains a series of Python scripts able to analyze the warts files
produced by `TNT`. They allow to study the performance of the tunnel revelation
tool, and to derive a few statistics about the deployment of MPLS in the probed
networks.


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
