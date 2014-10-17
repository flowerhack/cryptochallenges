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
