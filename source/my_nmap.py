#coding: utf8 
""" ITCR - IC8042
 David Chaverri Perez
 Tarea corta 4: 
 Python usando libreria scapy para emular algunos comandos de nmap
"""

from scapy.all import * #libreria scapy
import sys 				#entrada estandar del terminal (utilidad sys)

def ayuda():
	print ("ayuda en mantenimiento")
	sys.exit(1)

def revisarEntrada():
	#función para revisar los parámetros de entrada
	if len(sys.argv) != 3:
		if len(sys.argv) == 1:
			print ("Error - Faltan parámetros")
			print ("---help---")
			print ("Para ayuda digite: my_nmap -h")
			sys.exit(1)				
		elif sys.argv[1] == "-h":
			ayuda()
		else:
			print ("Error - Faltan parámetros")
			print ("---help---")
			print ("Para ayuda digite: my_nmap -h")
			sys.exit(1)
			
def TCP_Connect():
	print("TCP_Connect")
	
		
def opciones():
	if sys.argv[1] == "-sT":
		return TCP_Connect()
	else:
		print ("Error - opción inválida")
		print ("---help---")
		print ("Para ayuda digite:my_nmap -h")
		sys.exit(1)
	
"""		
	if sys.argv[1] == "-sS":
		return TCP_SYN()
	if sys.argv[1] == "-sA":
		return TCP_ACK()			
	if sys.argv[1] == "-sF":
		return TCP_FIN()		
	if sys.argv[1] == "-sI":
		return TCP_IDLE_SCAN()		
	if sys.argv[1] == "-sU":
		return TCP_UDP()			
"""

	
			
		
def main():
	revisarEntrada()
	opciones()


	

main() #llamado a función main()
	
