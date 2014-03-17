
""" ITCR - IC8042
 David Chaverri Perez
 Tarea corta 4: 
 Python usando libreria scapy para emular algunos comandos de nmap
"""

from scapy.all import * #libreria scapy
import sys 				#entrada estandar del terminal (utilidad sys)

def revisarEntrada():
	#función para revisar los parámetros de entrada
	if len(sys.argv) != 2:
		print ("----Error: Falta argumento Dirección IP-----")
		sys.exit(1)
		
def main():
	revisarEntrada()
	print ("dirección IP: "+ sys.argv[1])
	

main()
	

