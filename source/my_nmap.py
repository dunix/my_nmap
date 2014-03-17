from scapy.all import *
import sys

def revisarEntrada():	
	if len(sys.argv) != 2:
		print "----Falta dirección IP-----"
		sys.exit(1)
		
def main():
	revisarEntrada()
	print (sys.argv[1])

main()
	

