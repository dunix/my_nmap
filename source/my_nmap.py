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
	port = 0
	while port < 1023:
		# paso 1 ----> SYN
		ip = IP()
		ip.dst = sys.argv[2]
		tcp =TCP()
		tcp.flags = "S"
		tcp.dport = port	
		tcp.seq = 12
		resp1 = sr1(ip/tcp, timeout = 1, verbose=0)
		#verificación bandera
		try:
			x = resp1.summary()
		except:
			x= str(resp1)
		if x.find('SA') != -1:	
			# paso 2 <---- SYN ACK 
			tcp2 =TCP()
			tcp2.flags = "A"
			tcp2.dport = port
			tcp2.ack = resp1.seq +1
			# paso 1 ----> ACK
			resp2 = send(ip/tcp , verbose=0)
			print("Puerto: "+  str(tcp.dport) +" Open")
		else:
			# <---- RST 
			if x.find('R ') != -1:
				x="cerrado"
				#print("Puerto: "+  str(tcp.dport) +" Closed")
			else:
				if x == "None":
					#  ----> SYN
					print("Puerto: "+  str(tcp.dport) +" filtered")
		port= port+1
		
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
	

