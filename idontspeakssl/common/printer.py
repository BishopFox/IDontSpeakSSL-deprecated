from termcolor import colored, cprint


def print_start_message():
	cprint("#####################", 'white')
	cprint("#                   #", 'white')
	cprint("# I Don't Speak SSL #", 'white')
	cprint("#                   #", 'white')
	cprint("#####################", 'white')
	print()
	cprint("IDontSpeakSSL is tool working on sslyze ouput and generating HTML report", 'white')
	cprint("and highlight important findings that need to be reported.", 'white')	
	print()
