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

#TCP_Connect()
def TCP_Connect():
	print("------ Ejecutando TCP_Connect---------")
	port = 1
	contFiltered= 0
	contClosed = 0
	# paso 1 ----> SYN
	ip = IP()
	ip.dst = sys.argv[2]
	tcp =TCP()
	tcp.flags = "S"
	tcp.seq = 12
	# tcp2
	tcp2 =TCP()
	tcp2.flags = "A" #para completar el 3WH	
	while port < 81:
		tcp.dport = port	
		resp1 = sr1(ip/tcp, timeout = 0.5, verbose=0)
		#verificación bandera
		if (str(resp1) == "None"):
			contFiltered = contFiltered +1
		elif(resp1.haslayer(TCP)):
			if(resp1.getlayer(TCP).flags == 0x12):
				# paso 2 <---- SYN ACK 
				tcp2.dport = port
				tcp2.ack = resp1.seq +1
				# paso 3 ----> ACK
				resp2 = send(ip/tcp , verbose=0)
				print("Puerto: "+  str(tcp.dport) +" Estado: Open")
			elif (resp1.getlayer(TCP).flags == 0x14):
				contClosed = contClosed +1
		port= port+1
	print("Puertos Cerrados:  "+  str(contClosed))
	print("Puertos Filtrados: "+  str(contFiltered))

# TCP_SYN
def TCP_SYN():
	print("------ Ejecutando TCP_SYN---------")
	port = 1
	contFiltered = 0
	contClosed = 0
	# paso 1 ----> SYN
	ip = IP()
	ip.dst = sys.argv[2]
	tcp =TCP()
	tcp.flags = "S"
	tcp.seq = 12
	# tcp2
	tcp2 =TCP()
	tcp2.flags = "R" #para no completar el 3WH	send RST
	while port < 81:
		tcp.dport = port	
		resp1 = sr1(ip/tcp, timeout = 0.5, verbose=0)
		#verificación bandera
		if (str(resp1) == "None"):
			contFiltered = contFiltered +1
		elif(resp1.haslayer(TCP)):
			if(resp1.getlayer(TCP).flags == 0x12):
				# paso 2 <---- SYN ACK 
				tcp2.dport = port
				tcp2.ack = resp1.seq +1
				# paso 3 ----> ACK
				resp2 = send(ip/tcp , verbose=0)
				print("Puerto: "+  str(tcp.dport) +" Estado: Open")
			elif (resp1.getlayer(TCP).flags == 0x14):
				contClosed = contClosed +1
		port= port+1
	print("Puertos Cerrados:  "+  str(contClosed))
	print("Puertos Filtrados: "+  str(contFiltered))	
def opciones():
	if sys.argv[1] == "-sT":
		return TCP_Connect()
	if sys.argv[1] == "-sS":
		return TCP_SYN()		
		
	else:
		print ("Error - opción inválida")
		print ("---help---")
		print ("Para ayuda digite:my_nmap -h")
		sys.exit(1)
	
"""	
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
	

