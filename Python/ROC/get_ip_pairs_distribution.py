#!/usr/bin/env python

# ==============================================================================
# @(#)get_ip_pairs_distribution.py
# @date 2018/04/03
#
# @author Yves Vanaubel
#   Get the distribution of IP pairs according to their true/false
#   positive/negative classes.
# ==============================================================================


# IMPORT
import sys, os
from optparse import OptionParser

################################################################################

def main():
  usage = ("usage: %prog <classes_file> <output_file>\n"
           "  where:\n"
           "      - classes_file: file containing the different IP pairs"
           " and their classes.\n"
           "      - output_file is the output file.\n")
  parser = OptionParser(usage=usage)

  (options, args) = parser.parse_args()
  # Check arg number
  if not len(args)== 2:
    parser.print_help()
    sys.exit(1)

  classes_file = args[0]
  output_file_name = args[1]

  classes_file = open(classes_file, 'r')

  classes = ["TP", "FN", "FP", "IP", "TN", "IN"]
  class2nocc = dict()

  # Read input file
  for line in classes_file:
    line = line.strip()
    # Empty line
    if line == "" or "#" in line:
      continue
    line_split = line.split()
    # Get the classes for the pair
    c = list()
    for i in range(0,6):
      if int(line_split[i+1]) > 0:
        c.append(classes[i])
    fclass = "[" + ",".join(c) + "]"
    # Update distribution
    if fclass in class2nocc:
      class2nocc[fclass] += 1
    else:
      class2nocc[fclass] = 1

  # Write output file
  output_file = open(output_file_name, 'w')
  output_file.write("#Class nb_IP_pairs\n")
  for c in sorted(class2nocc, key=class2nocc.get, reverse=True):
    output_file.write(c + " " + str(class2nocc[c]) + "\n")
  output_file.close()
  os.system("column -t " + output_file_name + " > tmp_col.txt")
  os.system("mv tmp_col.txt " + output_file_name)
            
  return

if __name__ == '__main__':
	sys.exit(main())
