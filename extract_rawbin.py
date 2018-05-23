#!/usr/bin/python
#arg_parse.py
#coding:utf-8
import argparse
import cle
from capstone import *
import argparse
import os

def binary_loaded_info(app_bin, raw_bin=None):
    
    # First, get binary type: executable or shared object(PIE)
    bin_type = "executable"
    app_bin = os.path.realpath(app_bin)
    file_info = os.popen("file " + app_bin)
    if "shared object" in file_info.read():
        bin_type = "shared_object"
    print "binary type is ", bin_type
    
    # Now load binary, calculate program loaded base, entry, text_min and text_max 
    ld = cle.Loader(app_bin)
    bin_code = ""
        
    base_addr = ld.main_object.sections[0].vaddr
    entry = ld.main_object.entry
    for i in ld.main_object.sections:
        if i.name == ".text":
            text_min = i.vaddr
            text_max = i.vaddr + i.filesize
            raw_bytes = ld.memory.read_bytes(i.vaddr, i.filesize)
            for byte in raw_bytes:
                bin_code += byte
            #break
        
    #Third, write raw binary code to file
    if raw_bin == None:
        raw_bin = "." + os.path.basename(app_bin) + ".text"
    f = open(raw_bin, "wb")
    if not f:
        print "open file " + raw_bin + " for writing failed."
        sys.exit(-1)
        
    f.write(bin_code)
    f.close()
        
    # Now we have to recalcuate the loaded addresses for Position-independent executables
    if bin_type == "shared_object":
        text_min -= base_addr
        text_max -= base_addr
        entry -= base_addr
        base_addr = 0x0
        
        base_addr = 0x555555554000
        text_min += base_addr
        text_max += base_addr
        entry += base_addr
    
    bin_loaded_info = {
        'base': base_addr,
        'entry': entry,
        'text_min': text_min,
        'text_max': text_max,
        'raw_bin': raw_bin
        }
    return bin_loaded_info 

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Process an executable, output its raw binary and loaded address infomation.')
    parser.add_argument('binary', type = str, help = 'the executable binary.')
    parser.add_argument('-o', "--output-file", dest = "output", type = str, help = 'output raw binary to file.')
    args = parser.parse_args()
    
    
    info = binary_loaded_info(args.app_bin, args.output)
   
    print "base: ", hex(info['base'])
    print "entry: ", hex(info['entry'])
    print "text_min: ", hex(info['text_min'])
    print "text_max: ", hex(info['text_max'])
    print "raw_bin: ", info['raw_bin'] 



