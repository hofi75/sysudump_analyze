#!/usr/bin/python3

import os, re, sys, json
from memory import Memory
from CStruct import PCX, CStruct
import cProfile, pstats, io
# from pstats import SortKey

def main( arg):

	#pr = cProfile.Profile()
	#pr.enable()

	memory = Memory()
	memory.load_sysudump( arg[0])
	print( json.dumps( memory.dump( 0x24855860, 1024), sort_keys=False, indent=4))
	sys.exit()

	#pr.disable()
	#s = io.StringIO()
	#sortby = 'cumulative'
	##ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
	#ps.print_stats().print_stats(10)
	#print(s.getvalue())

	# cstr = CStruct

	pcx = PCX()
	print( json.dumps( pcx.get_value( memory, 0x24855860), sort_keys=False, indent=4))

if __name__ == "__main__":
	main( sys.argv[1:])
