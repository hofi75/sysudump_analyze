
from tqdm import tqdm
import os, re, sys
import profile, pstats, io


class Memory:

	PAGE_SIZE	= 4096

	cache_page = None
	cache_page_key = None

	def __init__(self):
		self.mpages = {}
		self.PAGE_MASK 		= 0xffffffff - self.PAGE_SIZE + 1
		self.OFFSET_MASK	= self.PAGE_SIZE - 1
		self.stop = 0
		print( "Memory: psize=%d,pmask=%.8X,omask=%.8X" % (self.PAGE_SIZE, self.PAGE_MASK, self.OFFSET_MASK))

	def set(self, address, byte):
		page_key	= address & self.PAGE_MASK
		offset		= address & self.OFFSET_MASK
		# print( "address[%.8X,pkey=%s,offset=%d] ==> %.2X" % (address, page_key, offset, byte))
		if self.cache_page_key == page_key:
			page = self.cache_page
		else:
			page = self.mpages.get(page_key, None)
			if page == None:
				page = bytearray(self.PAGE_SIZE)
				self.mpages[page_key] = page
			self.cache_page_key = page_key
			self.cache_page = page
		page[offset] = byte

	def dump( self, address: int, size):
		mb = self.get_memory_block( address, size)
		for i in range(0, size, 16):
			rslt["dump[%.8X:%.4X]" % (address + i, i) ] = bytearray.hex( mb[i:i+15])
		return rslt

#	@profile
	def set_bytearray( self, address, ba):
		page_key = address & self.PAGE_MASK
		offset = address & self.OFFSET_MASK
		if self.cache_page_key == page_key:
			page = self.cache_page
		else:
			page = self.mpages.get(page_key, None)
			if page == None:
#				print( "new page = 0x%.8X" % page_key)
				page = bytearray(self.PAGE_SIZE)
				self.mpages[page_key] = page
			self.cache_page_key = page_key
			self.cache_page = page
		balen = len(ba)
		page[offset:offset+balen-1] = ba
			

#	def set_string( self, address, s: str):
#		for i in range(len(s)):
#			self.set( address + i, ord(s[i]))

	def get(self, address):
		page_key	= address & self.PAGE_MASK
		offset		= address & self.OFFSET_MASK
		if self.cache_page_key == page_key:
			page = self.cache_page
		else:
			page = self.mpages.get(page_key, None)
			if page == None:
				return 0
			else:
				self.cache_page_key = page_key
				self.cache_page 	= page

		return page[offset]

	def get_pointer_be( self, address):
		ba = self.get_memory_block( address, 4)
		return int.from_bytes( ba, byteorder='big', signed=False)

	def dump_pages(self):
		for key, value in self.mpages.items():
			print(key)

	def get_memory_block( self, address, length) -> bytearray:
		area = bytearray(length)
		for i in range(length):
			area[i] = self.get( address + i)
		# print(area)
		return area

	def load_sysudump( self, filename, progress=True):

		print( "Loading file %s" %( filename))
		
		if progress:
			total = os.stat( filename).st_size 
			processed_bytes = 0
			pb = tqdm( total=total, unit="B", unit_scale=True, desc=filename, miniters=1, ncols=80, ascii=True)

		dumpline_regex = re.compile("\ ?([0-9]|[A-F]){8}\ ([0-9]|[A-F]){8}")
		lines_same_regex = re.compile( "\ {6,7}LINES ([0-9]|[A-F]|-)*\ *SAME AS ABOVE")

		with open( filename, "rt", encoding=None, errors='ignore') as f:
			for line in f:

				if progress:				
					processed_bytes += len(line)
					if processed_bytes >= 1024*256:
						pb.update(processed_bytes)
						processed_bytes = 0

				if dumpline_regex.match(line):
					base = line.split()[0]
					try:
						address = int(base,16)
						barray = bytearray.fromhex(line[9:83])
						self.set_bytearray( address, barray)
						save_barray = barray
					except ValueError:
						print( "Value error : %s" % line)
						pass
					continue
					
				# handle LINES .... SAME AS
				if lines_same_regex.match( line):
					addrs = line.split(maxsplit=2)[1].split('-')
					addr1 = int(addrs[0],16)
					addr2 = int(addrs[1],16)
					if addr2 == 0: 
						addr2 = addr1
					for address in range( addr1, addr2+1, 32):
						self.set_bytearray( address, save_barray)

					# print( "address(%.8X-%.8X)" % ( addr1, addr2))

			if progress:					
				pb.update(total)
				pb.close()