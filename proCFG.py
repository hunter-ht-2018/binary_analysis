import angr
from angrutils import plot_cfg
import sys, getopt

def main(argv):
   inputfile = ''
   outputfile = ''
   b_asminst = False        #show instruction or not
   b_vexinst = False        #show vex_ir or not
   long_parasest = ["inst","vex"]

   
   try:
      opts, args = getopt.getopt(argv,"i:o:",long_parasest)
   except getopt.GetoptError:
      print 'please input as format: python proCFG.py -i <inputfile> -o <outputimg> [inst][vex]'
      sys.exit(2)
   for opt, arg in opts:
      if opt not in ("-i","-o"):
         print 'please input as format: python proCFG.py -i <inputfile> -o <outputfile> [inst][vex]'
         sys.exit()
      elif opt in ("-i"):
         inputfile = arg
      elif opt in ("-o"):
         outputfile = arg

   for l_arg in args:
      if l_arg not in long_parasest:
          print 'please input as format: python proCFG.py -i <inputfile> -o <outputfile> [inst][vex]'
          sys.exit()
      elif l_arg in ("inst"):
          b_asminst = True
      elif l_arg in ("vex"):
          b_vexinst = True

   p = angr.Project(inputfile, load_options={'auto_load_libs': False})
   cfg = p.analyses.CFGAccurate()
   plot_cfg(cfg, outputfile, asminst=b_asminst, vexinst=b_vexinst)
if __name__ == "__main__":
   main(sys.argv[1:])