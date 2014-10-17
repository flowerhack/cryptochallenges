"""
This is very silly.  Basically, I wanted a convenient divisble-by-16-bytes
chunk o' text to test one of the encryption schemes, and I had the MGS3 theme
stuck in my head, so CLEARLY this meant it needed to be a line FROM THAT GAME
and this fetched all the possible candidates for me.

I will probably move it to a repo explicitly meant for silly things later.
"""

import re

prog = re.compile("[A-Za-z]+\: ")
with open("testfiles/metal_gear_solid_3_script.txt") as f:
	curline = ""
	for line in f:
		result = prog.match(line)
		if (result):
			curline = line.strip(result.group())
		elif line == "\n":
			valid_line = curline.replace("\n","")
			if (len(valid_line) % 16) == 0:
				print(valid_line)
				print()
			curline = ""
		else:
			curline = curline + line
