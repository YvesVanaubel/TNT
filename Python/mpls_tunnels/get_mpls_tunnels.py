#!/usr/bin/env python

# ==============================================================================
# @(#)get_mpls_tunnels.py
# @date 2018/04/03
#
# @author Yves Vanaubel
#   Read raw warts files collected with TNT from multiple VPs and extract MPLS
#   tunnels. Tunnels are considered as they appear, and multiple occurences of
#   the same tunnel may be found in the output file.
#
#   Output line format:
#     <vp_name> <tuntype> <tuntrig> <revmode> <buddy> <tunstatus> <hop> ...
#     ... <inv_trace_len> <vis_trace_len> => <tunnel> => <dst>
#    - vp_name is the name of the VP that saw the tunnel
#    - tuntype is the tunnel type: INV, EXP, IMP, OPA, HET
#      HET (heterogeneous) means a tunnel with some LSRs having a given type,
#      and others another type (e.g. explicit tunnel with some implicit LSRs).
#    - tuntrig is the tunnel trigger or indicator: RTLA, FRPLA, DUPIP, MTTL,
#      QTTL, UTURN, BTFC, MULTI (MTTL = MPLS TTL = LSE TTL, BTFC = Brute Force,
#      MULTI means the a part of the tunnel was revealed due to a given
#      indicator, and another part was due to another indicator. It may happens
#      when some implicit LSRs are observed in an explicit tunnel, for example)
#    - revmode is the tunnel revelation mode: DPR, BRPR, UNKN, ALLBUDDY, MIX.
#      ALLBUDDY means each LSR was revealed with the buddy technique.
#      UNKN is found when one could not determine the technique. It happens when
#      the LSP contains only one LSR (1HOP_LSP).
#      MIX means some LSRs were revealed with one technique, and others with
#      another technique.
#    - buddy is BUDDY if at least one LSR was revealed with the buddy technique.
#    - tunstatus is the tunnel status: COMP, INCOMP?
#      INCOMP? means that the tunnel may be incomplete, because the revelation
#      could not continue (target not reached, ingress not found, ...)
#    - hop is the hop number of the ingress in the trace
#    - inv_trace_len is the length of the trace with the tunnel not revealed
#    - vis_trace_len is the length of the trace with the tunnel revealed
#    - dst is the destination
#    - <tunnel> is in the form
#       <previous_IP> = <INGRESS> <LSR1>...<LSRn> <EGRESS> = <next_IP>
#   Each element in <tunnel> is in the form
#       IP:RTT:TE_ER_TTLs:[qTTL,uturn,frpla,rtla]:[revmode,step]:[labels,mTTL]
#       where:
#         > IP is the IP address
#         > RTT is the round trip time
#         > TE_ER_TTLs are the TTLs received in Time-Exceeded and Echo-Reply
#           messages, and written as <TE_TTL,ER_TTL>
#         > qTTL is the probe IP TTL quoted in the time-exceeded message.
#         > uturn is the computed uturn value
#         > frpla is the computed FRPLA value
#         > rtla is the computed RTLA value
#         > revmode is the mode used to reveal the LSR (DPR, BRPR, BUDDY, UNKN)
#           UNKN occurs only in case of 1HOP_LSP
#         > step is the revelation step at which the LSR was revealed
#         > labels are the MPLS labels observed for the LSR, written as
#           top_label|mid_label|bottom_label
#           Note that mid and bottom labels may not appear depending on the
#           stack size used in the LSP.
#         > mTTL is the top LSE TTL (i.e. only for the top LSE in the stack).
#   Note that some fields may be empty (-) if they do not have any value for
#   the element.
# ==============================================================================


# IMPORT
import sys, os, re, subprocess
from optparse import OptionParser
from os.path import basename

# Regex patterns
ip_pat = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
trace_re = re.compile(ip_pat + "\sto\s(" + ip_pat + ")")

################################################################################

# Find the destination of a trace based on the first line
# If not found, return *.
def get_trace_destination(trace_first_line):
  dst = trace_re.search(trace_first_line)
  if not dst:
    return "*"
  return dst.group(1)

################################################################################

# Read a line and store interesting fields into a list.
# hop_index is the position of the hop in the trace (invisible tunnels included)
# Output fields order:
#   0. Index of the hop in the trace
#   1. IP address
#   2. RTT
#   3. TTLs <TE,ER>
#   4. Node Type (ING, EGR, LSR) [list if node ingress and egress]
#   5. Tun. Type (INV, EXP, IMP, OPA) [list if node in two difrnt tunnels]
#   6. Tun. Trigger (RTLA, FRPLA, DUPIP, MTTL, QTTL, UTURN, BTFC)
#      [list if node in two difrnt tunnels ]
#   7. Node Rev. Techn (DPR, BRPR, UNKN, BUDDY, or -)
#   8. Node Rev. Step value or -
#   9. qTTL value or -
#   10. uturn value or -
#   11. FRPLA value or -
#   12. RTLA value or -
#   13. MPLS label value or -
#   14. mTTL value for top label or -
#   15. tunnel status (incomplete or not)
def read_line(line, hop_index):
  line_fields = list()
  
  # Empty line
  if line == "":
    for i in range(0, 15):
      line_fields.append("-")
    line_fields[1] = "*"
    for i in range(4, 7):
      line_fields[i] = list()
    return line_fields

  line_split = line.split()
  nelmt = len(line_split)

  # Position
  line_fields.append(str(hop_index))

  # IP address
  ip = line_split[1]
  line_fields.append(ip)

  # Non responding node
  if ip == "*":
    for i in range(2, 16):
      line_fields.append("-")
    for i in range(4, 7):
      line_fields[i] = list()
    return line_fields
  
  # RTT
  rtt = line_split[2]
  line_fields.append(rtt)

  # Other elements may be optional
  ttls = "-"
  qttl = "-"
  ntype = list()
  tuntype = list()
  tuntrig = list()
  nrev = "-"
  nrevstep = "-"
  frpla = "-"
  rtla = "-"
  labels = "-"
  mttl = "-"
  uturn = "-"
  tunstatus = "-"
  
  for i in range(4, nelmt):
    elmt = line_split[i]
    # TE and ER TTLs
    if "rTTLs=" in elmt:
      ttls = elmt.split("=")[-1]
    # Quoted TTL
    elif "qttl=" in elmt:
      qttl = elmt.split("=")[-1]
    # Uturn value
    elif "uturn=" in elmt:
      uturn = elmt.split("=")[-1]
    # FRPLA value
    elif "frpla=" in elmt:
      frpla = elmt.split("=")[-1]
    # RTLA value
    elif "rtla=" in elmt:
      rtla = elmt.split("=")[-1]
    # MPLS labels
    elif elmt == "Labels":
      i += 1
      labels = line_split[i]
      while i<nelmt-2 and line_split[i+2] == "|":
        i += 3
        labels += "|" + line_split[i]
    # LSE TTL (for top label only)
    elif "mTTL=" in elmt and mttl == "-":
      mttl = elmt.split("=")[-1]
    elif "MPLS" in elmt:
      elmt_split = elmt[1:-1].split(",")
      for subelmt in elmt_split:
        # Tunnel type
        if (subelmt == "EXP" or subelmt == "IMP" or
            subelmt == "INV" or subelmt == "OPA"):
          tuntype.append(subelmt)
        # Node type
        elif subelmt == "LSR" or subelmt == "ING" or subelmt == "EGR":
          ntype.append(subelmt)
        # Node revelation technique
        elif (subelmt == "BRPR" or subelmt == "DPR" or
              subelmt == "UNKN" or subelmt == "BUDDY"):
          nrev = subelmt
        # Revelation step
        elif "step=" in subelmt:
          nrevstep = subelmt.split("=")[-1]
        # Tunnel trigger/indicator
        elif (subelmt == "FRPLA" or subelmt == "RTLA" or subelmt == "DUPIP" or
              subelmt == "QTTL" or subelmt == "UTURN" or subelmt == "MTTL" or
              subelmt == "BTFC"):
          tuntrig.append(subelmt)
        # Incomplete tunnel
        elif subelmt == "INCOMP?":
          tunstatus = "INCOMP?"

  line_fields.append(ttls)
  line_fields.append(ntype)
  line_fields.append(tuntype)
  line_fields.append(tuntrig)
  line_fields.append(nrev)
  line_fields.append(nrevstep)
  line_fields.append(qttl)
  line_fields.append(uturn)
  line_fields.append(frpla)
  line_fields.append(rtla)
  line_fields.append(labels)
  line_fields.append(mttl)
  line_fields.append(tunstatus)
  
  return line_fields

################################################################################

# Add a hop in a tunnel
def add_hop(hop_fields, tunnel):

  # IP address
  ip = hop_fields[1]
  # Non responding node
  if ip == "*":
    tunnel.append("*")
    return
  output_list = [ip]

  # RTT
  rtt = hop_fields[2]
  output_list.append(rtt)

  # TTLs
  ttls = hop_fields[3]
  output_list.append(ttls)

  # qTTL, UTURN, FRPLA and RTLA
  qttl = hop_fields[9]
  uturn = hop_fields[10]
  frpla = hop_fields[11]
  rtla = hop_fields[12]
  output_list.append("[" + qttl + "," + uturn + "," + frpla + "," + rtla + "]")

  # Revelation mode and step
  revmode = hop_fields[7]
  revstep = hop_fields[8]
  output_list.append("[" + revmode + "," + revstep + "]")

  # MPLS labels and LSE TTL
  labels = hop_fields[13]
  mTTL = hop_fields[14]
  output_list.append("[" + labels + "," + mTTL + "]")

  tunnel.append(":".join(output_list))
  return


################################################################################

# Print a tunnel into the output file
def print_tunnel(tunnel, output_file, vp_name, vis_trace_len,
                 inv_trace_len, dst):
    
  tunnel_str = list()
  
  # Get the different hops
  hop = tunnel[1][0]
  tlen = len(tunnel)
  nstars = 0
  tunnel_types = set()
  tunnel_triggers= set()
  tunnel_rev_modes = set()
  ingress_types = set()
  ingress_triggers = set()
  egress_types = set()
  egress_triggers = set()
  tunstatus = "-"
  for i in range(0, tlen):
    hop_fields = tunnel[i]
    add_hop(hop_fields, tunnel_str)
    if i == 0 or i == tlen - 2:
      tunnel_str.append("=")
    # Ingress
    if i == 1:
      if hop_fields[5]:
        for hf in hop_fields[5]:
          ingress_types.add(hf)
      if hop_fields[6] != "-":
        for hf in hop_fields[6]:
          ingress_triggers.add(hf)
      if hop_fields[-1] == "INCOMP?":
        tunstatus = hop_fields[-1]
    # Egress
    if i == tlen-2:
      if hop_fields[5]:
        for hf in hop_fields[5]:
          egress_types.add(hf)
      if hop_fields[6] != "-":
        for hf in hop_fields[6]:
          egress_triggers.add(hf)
      tunnel_rev_modes.add(hop_fields[7]);
      if hop_fields[1] == "*":
        nstars += 1
    # LSP
    if i > 1 and i < tlen - 2:
      if hop_fields[5]:
        for hf in hop_fields[5]:
          tunnel_types.add(hf)
      if hop_fields[6] != "-":
        for hf in hop_fields[6]:
          tunnel_triggers.add(hf)
      tunnel_rev_modes.add(hop_fields[7])
      if hop_fields[1] == "*":
        nstars += 1

  # Get the tunnel type
  tuntype = ""
  # Check LSP
  if len(tunnel_types) == 1:
    tuntype = tunnel_types.pop()
    if len(ingress_types) == 1:
      ingtype = ingress_types.pop()
      if tuntype != ingtype:
        tuntype = "HET"
    elif len(egress_types) == 1:
      egtype = egress_types.pop()
      if tuntype != egtype:
        tuntype = "HET"
  elif len(tunnel_types) > 1:
    tuntype = "HET"
  # Check egress
  elif len(egress_types) == 1:
    tuntype = egress_types.pop()
  # Check ingress
  elif len(ingress_types) == 1:
    tuntype = ingress_types.pop()
  # Check ingress and egress
  elif len(ingress_types.intersection(egress_types)) == 1:
    tuntype = ingress_types.intersection(egress_types).pop()
  # Worst case
  elif (len(egress_types) == 0 and len(ingress_types) == 0
        and len(tunnel_types) == 0):
    tuntype = "INV"
  else:
    tuntype = "UNKN"
    utypes = ingress_types.union(egress_types)
    if "OPA" in utypes and not "INV" in utypes:
      tuntype = "OPA"
    elif "INV" in utypes and not "OPA" in utypes:
      tuntype = "INV"
  
  
  tuntrig = "-"
  # Check LSP
  if len(tunnel_triggers) == 1:
    tuntrig = tunnel_triggers.pop()
  elif len(tunnel_triggers) > 1:
    tuntrig = "MULTI"
  # Check egress
  elif len(egress_triggers) == 1 and tuntype != "EXP":
    tuntrig = egress_triggers.pop()
  # Check ingress
  elif len(ingress_triggers) == 1 and tuntype != "EXP":
    tuntrig = ingress_triggers.pop()
  # Check ingress and egress
  elif (len(ingress_triggers.intersection(egress_triggers)) == 1 and
        tuntype != "EXP"):
    tuntrig = ingress_triggers.intersection(egress_triggers).pop()
  # DUPIP
  elif tuntype == "INV":
    tuntrig = "DUPIP"
  elif tuntype != "EXP":
    tuntrig = "UNKN"
  
  # Get the revelation mode
  revmode = "-"
  buddy = "-"
  if "BUDDY" in tunnel_rev_modes:
    buddy = "BUDDY"
    tunnel_rev_modes.remove("BUDDY")
  nrevmodes = len(tunnel_rev_modes)
  if nrevmodes == 0:
    if buddy == "BUDDY":
      revmode = "ALLBUDDY"
    else:
      print "NO REVMODE DETECTED"
  else:
    if "-" in tunnel_rev_modes:
      tunnel_rev_modes.remove("-")
      nrevmodes -= 1
    if nrevmodes > 1:
      revmode = "MIX"
    elif nrevmodes == 1:
      revmode = tunnel_rev_modes.pop()
      if revmode == "BRPR" and nstars > 1:
        revmode = "MIX"
    elif nrevmodes == 0 and (tuntype == "INV" or tuntype == "OPA"):
      if nstars > 1:
        revmode = "DPR"
      elif nstars == 1:
        revmode = "UNKN"
  
  # Update tunnel status if needed
  if tunstatus == "-" and tuntype == "INV":
    tunstatus = "COMP"

  output_file.write(vp_name + " " + tuntype + " " + tuntrig +
                    " " + revmode + " " + buddy + " " + tunstatus + " " + hop +
                    " " + str(inv_trace_len) + " " + str(vis_trace_len) +
                    " => " + " ".join(tunnel_str) + " => " + dst + "\n")
  return

################################################################################

# Add to a tunnel a hop found at a given index in a trace
def add_tunnel_hop(trace, index, tunnel):
  if index < 0 or index >= len(trace):
    hop = read_line("", index)
  else:
    hop = read_line(trace[index], index)
  tunnel.append(hop)
  return

################################################################################

# Find MPLS tunnels in a trace and output them
def output_trace_tunnels(trace, output_file, vp_name):
  if not trace:
    return
  
  # Get the destination and traces length
  dst = get_trace_destination(trace[0])
  vis_trace_len = len(trace) - 1
  inv_trace_len = trace[-1].split()[0]
  
  # Will contain the tunnel
  tunnel = list()
  # Will contain the revelation modes observed for this tunnel
  revmodes = set()
  
  # Read the trace
  i = 1
  while i < vis_trace_len+1:
    line = trace[i]
    line_elmts = read_line(line, i)
    next_line = ""
    if i < vis_trace_len:
      next_line = trace[i+1]
    next_line_elmt = read_line(next_line, i+1)
    ntype = ""

    # Check if egress node
    if "EGR" in line_elmts[4]:
      # Non-responding ingress
      if not tunnel:
        if (trace[i-1].split()[1] == "*" and
            (line.startswith("H") or "OPA" in line_elmts[5])):
          # Add previous node
          add_tunnel_hop(trace, i-2, tunnel)
          # Add ingress
          add_tunnel_hop(trace, i-1, tunnel)
        else:
          return
      ntype = "LER"
      tunnel.append(line_elmts)
      # Add the next hop
      add_tunnel_hop(trace, i+1, tunnel)
      # Print the tunnel
      print_tunnel(tunnel, output_file, vp_name, vis_trace_len,
                   inv_trace_len, dst)
      del tunnel[:]

    # Check if ingress node
    if "ING" in line_elmts[4]:
      ntype = "LER"
      if tunnel:
        # Here, can not be egress otherwise tunnel is empty
        # Close the previous tunnel.
        
        # Previous hop is *, as expected
        if trace[i-1].split()[1] == "*":
          # Add egress
          add_tunnel_hop(trace, i-1, tunnel)
          # Add the next hop
          tunnel.append(line_elmts)
        # Something strange
        else:
          return
        # Print the tunnel
        print_tunnel(tunnel, output_file, vp_name, vis_trace_len,
                     inv_trace_len, dst)
        del tunnel[:]
      
      # Add the previous node
      add_tunnel_hop(trace, i-1, tunnel)
      # Add the ingress node
      tunnel.append(line_elmts)

    # If LER router, can not be also an internal LSR in the same trace
    if ntype == "LER":
      i += 1
      continue
    
    # Internal node
    if "LSR" in line_elmts[4]:
      # Tunnel is empty => ingress did not respond
      if not tunnel:
        # Previous hop is *, as expected
        prev_line_elmts = read_line(trace[i-1], i-1)
        if prev_line_elmts[1] == "*":
          if (prev_line_elmts[9] != "-" and int(prev_line_elmts[9]) == 2 and
              i > 2 and trace[i-3].split()[1] == "*"):
            add_tunnel_hop(trace, i-3, tunnel)
          add_tunnel_hop(trace, i-2, tunnel)
          add_tunnel_hop(trace, i-1, tunnel)
        else:
          return
      # Add the LSR
      tunnel.append(line_elmts)

    # Node not flagged as MPLS
    if len(line_elmts[4]) == 0:
      if line_elmts[1] == "*":
        # Egress with duplicate IP address
        if line.startswith("H"):
          if not tunnel:
            if trace[i-1].split()[1] == "*":
              # Add the previous node
              add_tunnel_hop(trace, i-2, tunnel)
              # Add the ingress node
              add_tunnel_hop(trace, i-1, tunnel)
            else:
              return
            # Add the LSR
            tunnel.append(line_elmts)
          else:
            # Add the LSR
            tunnel.append(line_elmts)
            if not next_line.startswith("H") and not "MPLS" in next_line:
              # Add the next node
              add_tunnel_hop(trace, i+1, tunnel)
              print_tunnel(tunnel, output_file, vp_name, vis_trace_len,
                           inv_trace_len, dst)
              del tunnel[:]
        elif tunnel:
          # Add the LSR
          tunnel.append(line_elmts)
          prev_line_elmts = read_line(trace[i-1], i-1)
          # Check previous hop
          if ("IMP" in prev_line_elmts[5] and
              ((prev_line_elmts[9] != "-" and int(prev_line_elmts[9]) > 1) or
               (next_line_elmt[9] != "-" and int(next_line_elmt[9]) == 2) or
               ("UTURN" in prev_line_elmts[6] and prev_line_elmts[10] != "-" and
                int(prev_line_elmts[10]) != 0 and
                prev_line_elmts[10] != prev_line_elmts[12]))):
              i += 1
              continue
          # Add the next node
          add_tunnel_hop(trace, i+1, tunnel)
          print_tunnel(tunnel, output_file, vp_name, vis_trace_len,
                       inv_trace_len, dst)
          del tunnel[:]
      elif tunnel:
        # Duplicate IP with non responding egress
        if line_elmts[1] == next_line_elmt[1]:
          # Add the next hop
          tunnel.append(line_elmts)
          print_tunnel(tunnel, output_file, vp_name, vis_trace_len,
                       inv_trace_len, dst)
          del tunnel[:]
        else:
          return

    i += 1
  return

################################################################################

# Read a warts file and get traces. Traces are a lists of their lines.
def read_warts_traces(warts_file, output_file, vp_name):
  trace_file_name = "traces_mpls_tunnels_" + warts_file.split("/")[-1] + ".txt"
  
  # Uncompress if necessary
  current_input_file_name = warts_file
  if warts_file.endswith(".gz"):
    current_input_file_name = basename(warts_file.split(".gz")[0])
    os.system("gunzip -c " + warts_file + " > " + current_input_file_name)

  cmd = "sc_tnt -d1 " + current_input_file_name + " > " + trace_file_name
  os.system(cmd)

  current_trace = list()
  current_dst = ""
  tmp_trace_file = open(trace_file_name)
  for line in tmp_trace_file:
    line = line.strip()
    if line == "" or "#" in line:
      continue

    # New trace
    if "trace" in line:
      output_trace_tunnels(current_trace, output_file, vp_name)
      current_trace = [line]
    # Copy the trace's content
    else:
      current_trace.append(line)

  # Check the last trace of the file
  output_trace_tunnels(current_trace, output_file, vp_name)
  
  tmp_trace_file.close()
  os.system("rm " + trace_file_name)

  # Delete uncompressed file if necessary
  if warts_file.endswith(".gz"):
    os.system("rm " + current_input_file_name)

################################################################################

def main():
  usage = ("usage: %prog <vps_warts_dir> <output_file>\n"
           "  where:\n"
           "      - vps_warts_dir is the directory containing the traces "
           "collected by each VP during the campaign.\n"
           "        Format: <vps_warts_dir>/<VP>/<VP_cycle>.warts\n"
           "      - output_file is the output file.\n")
  parser = OptionParser(usage=usage)

  (options, args) = parser.parse_args()
  # Check arg number
  if not len(args)== 2:
    parser.print_help()
    sys.exit(1)

  traces_dir = args[0]
  output_file = args[1]

  # Output file
  output_file = open(output_file, 'w')

  # Consider all VPs
  cmd = "ls " + traces_dir
  vps = subprocess.check_output(cmd, shell=True).split()
  for vp in vps:
    current_dir = traces_dir + "/" + vp
    cmd = "ls " + current_dir
    warts_files = subprocess.check_output(cmd, shell=True).split()
  
    # Read each warts file for the VP and find tunnels
    for warts_file in warts_files:
      read_warts_traces(current_dir + "/" + warts_file, output_file, vp)

  output_file.close()
  return

if __name__ == '__main__':
	sys.exit(main())
