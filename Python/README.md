TNT - Python Scripts
============================

`TNT` (Trace the Naughty Tunnels) [1,2] is an extension to Paris traceroute for
revealing most (if not all) hidden MPLS tunnels along a path.

This README presents a series of Python scripts able to analyze the warts files
produced by `TNT`. They allow to study the performance of the tunnel revelation
tool, and to derive a few statistics about the deployment of MPLS in the probed
networks.

Note that the usage as well as non-trivial output formats are written in the
header of each Python script.

The scripts are organized into five directories:
  * *ip_addresses*: scripts in charge of collecting IP addresses
  * *mpls_tunnels*: scripts in charge of extracting MPLS tunnels from `TNT` warts
                  files.
  * *probe_cost*: scripts in charge of computing the probe cost of `TNT`
  * *ROC*: scripts in charge of computing the data for a ROC curve describing
         the performance of `TNT`
  * *stats*: scripts in charge of computing a few stats about the collected MPLS
           tunnels, such as their number, or the distribution of LSE TTL values.




Requirements
---------------------

The different scripts were developped under **Python 2.7.10**.
They do not require any non-standard Python module.
`TNT` must be installed on the machine before running the different scripts.
For more information, refer to `TNT`'s README file and implementation.

Datasets on which the different scripts can be run are available at:




IP Addresses
---------------------

The directory *ip_addresses* contains the Python script *read_warts_ips.py* able
to collect the different IP addresses (destinations excluded) observed during
a `TNT` measurement campaign. They are written 1 by line into an output file.

It can be run on a measurement campaign to extract the different IP addresses
observed by the different monitors.

```
Usage: read_warts_ips.py <vps_warts_dir> <output_file>
where:
  - vps_warts_dir is the directory containing the traces collected by each
    VP during the campaign.
    Format: <vps_warts_dir>/<VP>/<VP_cycle>.warts
  - output_file is the output file.
```

Example of usage:
```
> python read_warts_ips.py dataset_20180423/ ip_addresses.txt
```


MPLS Tunnels
---------------------

The directory *mpls_tunnels* contains the Python script *get_mpls_tunnels.py* able
to extract the different MPLS tunnels from warts files collected durinf a `TNT`
measurement campaign.

Each tunnel is written on a single line in the output file. Tunnels are
considered as they appear, and multiple occurences of the same tunnel may be
found in the output file. The format of an output line is described in the
header of the script.

```
Usage: get_mpls_tunnels.py <vps_warts_dir> <output_file>
where:
  - vps_warts_dir is the directory containing the traces collected by each VP
    during the campaign.
    Format: <vps_warts_dir>/<VP>/<VP_cycle>.warts
  - output_file is the output file.
```

Example of usage:
```
> python get_mpls_tunnels.py dataset_20180423/ tunnels.txt
```



Probe Cost
---------------------

The directory *probe_cost contains* the Python script *compute_tnt_cost.py* able
to determine the cost of the tunnel revelation performed by `TNT` in terms of
quantity of probes sent.

The ouptut file differentiates the probes sent for traces, pings and pings
performed for the buddy technique. The format of an output line is described
in the header of the script.

```
Usage: compute_tnt_cost.py <vps_warts_dir> <output_file>
where:
  - vps_warts_dir is the directory containing the traces collected by each VP
    during the campaign.
    Format: <vps_warts_dir>/<VP>/<VP_cycle>.warts
  - output_file is the output file.
```

Example of usage:
```
> python compute_tnt_cost.py dataset_20180423/ probe_cost.txt
```



ROC
---------------------

The directory *ROC* contains three Python scripts. The main script, called
*get_ROC_data.py* computes the data for a ROC curve describing the performance
of `TNT` according to RTLA and FRPLA threshold values. The warts files used to
compute the ROC must have been collected by `TNT` in brute force mode.

```
Usage: get_ROC_data.py <vps_warts_dir> <output_dir>
where:
    - vps_warts_dir is the directory containing the traces collected by each
      VP during the brute force campaign.
      Format: <vps_warts_dir>/<ij>/<VP>/<VP>-<ij>.warts
              with i the FRPLA threshold value and j the RTLA threshold value
    - output_dir is the output directory.
```

The ROC data is stored in an output file named *ROC_data.txt* written in the
output directory.

Example of usage:
```
> python get_ROC_data.py dataset_20180406/ roc_directory
```

The two other Python scripts *analyze_pos_neg.py* and *get_ip_pairs_distribution.py*
are called by the main script *get_ROC_data.py*. They store temporary results in
the output directory that are deleted at the end of the execution.
More details about these two scripts can be found in their respective headers.




Stats
---------------------

The directory stats contains two Python scripts.

The first script, *count_tunnels.py*, counts the different types of tunnels
(IP based) observed in a measurement campaign. It also determine the tunnel
distribution according to their triggers and their revelation techniques.
The structure of the input directory as well as the format of the output
files are described in the header of the script.

```
Usage: count_tunnels.py <tunnels_file> <output_dir> <vp_name>
where:
  - tunnels_file is the file containing all the tunnels to be classified.
    This file is obtained with the Python script get_mpls_tunnels.py presented
    peviously.
  - output_dir is the output directory.
  - vp_name is the name of the VP (monitor) to consider. 'all' means all VPs.
```

Example of usage:
```
> python count_tunnels.py tunnels.txt tunnel_count_directory all
```

The second script, called *count_lse_ttls.py* computes the distribution of LSE TTL
values observed in warts files collected with `TNT` (only for the top LSE of the
label stack). All occurences of LSE TTLs are considered as they appear in the
different traces. No kind of sorting is applied.

```
Usage: count_lse_ttls.py <vps_warts_dir> <output_file>
where:
  - vps_warts_dir is the directory containing the traces collected by each VP
    during the campaign.
    Format: <vps_warts_dir>/<VP>/<VP_cycle>.warts
  - output_file is the output file.
```

Example of usage:
```
> python count_lse_ttls.py dataset_20180423/ lse_ttl_distr.txt
```



References
---------------------

[1] Y. VANAUBEL, P. MERINDOL, J.-J. PANSIOT, and B. DONNET,
Through the Wormhole: Tracking Invisible MPLS Tunnels,
Proceedings of the 2017 Conference on Internet Measurement Conference

[2] Y. VANAUBEL, P. MERINDOL, J.-J. PANSIOT, and B. DONNET,
TNT, Watch me Explode: A Light in the Dark for Revealing All MPLS Tunnels




Authors
---------------------

**Implementation**:
Y. VANAUBEL

**Contributors**:
P. MERINDOL
J.-J. PANSIOT
B. DONNET

Contact: [http://www.montefiore.ulg.ac.be/~bdonnet/mpls/contact.html](http://www.montefiore.ulg.ac.be/~bdonnet/mpls/contact.html)




License
---------------------

The project is licensed under the GPLv2.
