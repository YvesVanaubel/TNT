#!/usr/bin/env python

# ==============================================================================
# @(#)get_ROC_data.py
# @date 2018/04/05
#
# @author Yves Vanaubel
#   Get data for the ROC curve describing the performance of TNT according to
#   RTLA and FRPLA threshold values. The warts files must have been collected
#   during a brute force campaign.
#   The script produces in the output directory an output file called
#   ROC_data.txt that contains true/false positive/negative values for each
#   combination of FRPLA and RTLA threshold values:
#     - TP = True Positive
#     - FP = False Positive
#     - TN = True Negative
#     - FN = False Negative
#   Then, TPR can easily be computed as TP / (TP + FN) and FPR as FP / (FP + TN)
#   Note that the output directory is used to store intermediate results needed
#   to compute the ROC data.
# ==============================================================================


# IMPORT
import sys, os, subprocess
from optparse import OptionParser
from os.path import basename

################################################################################

def main():
  usage = ("usage: %prog <vps_warts_dir> <output_dir>\n"
           "  where:\n"
           "      - vps_warts_dir is the directory containing the traces "
           "collected by each VP during the brute force campaign.\n"
           "        Format: <vps_warts_dir>/<ij>/<VP>/<VP>-<ij>.warts\n"
           "                with i the FRPLA threshold value and j the RTLA"
           " threshold value\n"
           "      - output_dir is the output directory.\n")
  parser = OptionParser(usage=usage)

  (options, args) = parser.parse_args()
  #Check arg number
  if not len(args)== 2:
    parser.print_help()
    sys.exit(1)

  vps_warts_dir = args[0]
  output_dir = args[1]

  os.system("rm -r " + output_dir + " ; mkdir " + output_dir)
  raw_dir = output_dir + "/raw"
  os.system("mkdir " + raw_dir)
  classes_dir = output_dir + "/classes"
  os.system("mkdir " + classes_dir)

  # For each combination of RTLA/FRPLA threshold values, determine true/false
  # positive/negative classes for each possible entry/exit IP pair of an
  # invisible MPLS tunnel.
  cmd = "ls " + vps_warts_dir
  combinations = subprocess.check_output(cmd, shell=True).split()
  for comb in combinations:
    idir = vps_warts_dir + "/" + comb
    odir = raw_dir + "/" + comb
    os.system("mkdir " + odir)
    os.system("python analyze_pos_neg.py " + idir + " " + odir)

  # Get the distribution of IP pairs according to their classes
  for comb in combinations:
    idir = raw_dir + "/" + comb
    odir = classes_dir + "/" + comb
    os.system("mkdir " + odir)
    for type in ["all", "RTLA", "FRPLA", "MTTL", "DUPIP"]:
      ifile = idir + "/" + type + ".txt"
      ofile = odir + "/classes_" + type + ".txt"
      os.system("python get_ip_pairs_distribution.py " + ifile + " " + ofile)

  # Read the distributions for each combination, and select the classes.
  # Inconclusive classes are not taken into account for the ROC curve.
  classes = ["TP", "FP", "FN", "TN"]
  ofile_name = output_dir + "/ROC_data.txt"
  ofile = open(ofile_name, 'w')
  ofile.write("#(FRPLA,RTLA) TP FP FN TN\n")
  for comb in combinations:
    idir = classes_dir + "/" + comb
    ifile = idir + "/classes_all.txt"
    frpla = comb[0]
    rtla = comb[1]

    # Select the classes for the combination
    ifile = open(ifile)
    d = dict()
    d["comb"] = "(f" + frpla + ",r" + rtla + ")"
    for c in classes:
      d[c] = 0
    for line in ifile:
      line = line.strip()
      if line == "" or "#" in line:
        continue
      line_split = line.split()
      c = line_split[0][1:-1]
      if c in classes:
        nocc = line_split[1]
        d[c] = nocc
    # Output the line
    ofile.write(d["comb"] + " " + d["TP"] + " " + d["FP"] + " " + d["FN"] +
                " " + d["TN"] + "\n")

  ifile.close()
  ofile.close()
  # Arrange the output file
  os.system("column -t " + ofile_name +
            " > tmp_col.txt; mv tmp_col.txt " + ofile_name)

  # Delete directories used for temporary results
  os.system("rm -r " + raw_dir + " " + classes_dir)
  return

if __name__ == '__main__':
	sys.exit(main())
