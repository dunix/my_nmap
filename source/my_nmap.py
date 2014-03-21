#coding: utf8 
""" ITCR - IC8042
 David Chaverri Perez
 Tarea corta 4: 
 Python usando libreria scapy para emular algunos comandos de nmap
"""

from scapy.all import * #libreria scapy
import sys 				#entrada estandar del terminal (utilidad sys)


def ayuda():
	print ("---Ayuda my_nmap---")
	print ("-----Sintaxis------")
	print ("my_nmap opcion IP_target")
	print ("my_nmap -sT target")
	print ("my_nmap -sS target")
	print ("my_nmap -sA target")
	print ("my_nmap -sF target")
	print ("my_nmap -sU target")
	print ("my_nmap -sI zombie target port")
	
	sys.exit(1)

def revisarEntrada():
	#función para revisar los parámetros de entrada
	if (len(sys.argv) != 3 and len(sys.argv) != 5):
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
	while port < 1024:
		tcp.dport = port	
		resp1 = sr1(ip/tcp, timeout = 1, verbose=0)
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
	while port < 1024:
		tcp.dport = port	
		resp1 = sr1(ip/tcp, timeout = 1, verbose=0)
		#verificación bandera
		if (str(resp1) == "None"):
			contFiltered = contFiltered +1
		elif(resp1.haslayer(TCP)):
			if(resp1.getlayer(TCP).flags == 0x12):
				# paso 2 <---- SYN ACK 
				tcp2.dport = port
				tcp2.ack = resp1.seq +1
				# paso 3 ----> RST
				resp2 = send(ip/tcp , verbose=0)
				print("Puerto: "+  str(tcp.dport) +" Estado: Open")
			elif (resp1.getlayer(TCP).flags == 0x14):
				contClosed = contClosed +1
		port= port+1
	print("Puertos Cerrados:  "+  str(contClosed))
	print("Puertos Filtrados: "+  str(contFiltered))

#TCP_ACK()
def TCP_ACK():
	print("------ Ejecutando TCP_ACK---------")
	port = 1
	unFiltered = 0
	# paso 1 ----> ACK
	ip = IP()
	ip.dst = sys.argv[2]
	tcp =TCP()
	tcp.ack = 5
	tcp.flags = "A"
	while port < 1024:
		tcp.dport = port	
		resp1 = sr1(ip/tcp, timeout = 10, verbose=0)
		#verificación bandera
		if (str(type(resp1))=="<type 'NoneType'>"):
			print("filtrado: " + str(port))
		elif (resp1.haslayer(ICMP)):
			if(int(resp1.getlayer(ICMP).type)==3):
				print("filtrado: " + str(port))		
		else:
			unFiltered =  unFiltered +1
		port = port +1
	
	print("Puertos no filtrados:  "+  str(unFiltered))

def TCP_FIN():
	print("------ Ejecutando TCP_FIN---------")
	port = 1
	OpenFiltered = 0
	# paso 1 ----> FIN
	ip = IP()
	ip.dst = sys.argv[2]
	tcp =TCP()
	tcp.ack = 5
	tcp.flags = "F"
	while port < 1024:
		tcp.dport = port	
		resp1 = sr1(ip/tcp, timeout = 2, verbose=0)
		#verificación bandera
		if (str(type(resp1))=="<type 'NoneType'>"): #packs sin respuesta
			OpenFiltered =  OpenFiltered +1
		elif(resp1.haslayer(TCP)):
			if (resp1.getlayer(TCP).flags == 0x14):
				print("Cerrado: " + str(port))	
		else:
			OpenFiltered =  OpenFiltered +1
		port = port +1
	
	print("Puertos Abiertos/filtrados:  "+  str(OpenFiltered))

def TCP_UDP():
	print("------ Ejecutando TCP_UDP---------")
	port = 1
	OpenFiltered = 0
	ip = IP()
	ip.dst = sys.argv[2]
	udp =UDP()
	while port < 1024:
		udp.dport = port	
		resp1 = sr1(ip/udp, timeout = 5, verbose=0)
		#verificación bandera
		if (str(type(resp1))=="<type 'NoneType'>"): #packs sin respuesta
			OpenFiltered =  OpenFiltered +1
		elif(resp1.haslayer(ICMP)):
			if(int(resp1.getlayer(ICMP).type)==3):
				if(int(resp1.getlayer(ICMP).code)==3): #ICMP #3 t&c = 3
					print("Cerrado: " + str(port))	
		else:
			OpenFiltered =  OpenFiltered +1
		port = port +1
	print("Puertos Abiertos/filtrados:  "+  str(OpenFiltered))
	
def TCP_IDLE_SCAN(): # my_nmap -sI zombie target Zombieport
	print("------ Ejecutando TCP_IDLE_SCAN---------")
	ipCount = 0
	Filtered = 0
	closed = 0
	# Paquete IP
	ip1 = IP()
	ip1.dst = sys.argv[2]
	tcp1 =TCP()
	tcp1.flags = "SA"
	tcp1.dport = int(sys.argv[4])
	#envio SA al zombie
	resp1 = sr1(ip1/tcp1, timeout = 1, verbose=0)
	if (str(type(resp1))=="<type 'NoneType'>"): #packs sin respuesta
			print("Puerto Zombie Filtrado")
	elif(resp1.haslayer(TCP)): #Verifica puerto no filtrado
		print("---Escaneando Target---")
		if (resp1.getlayer(TCP).flags == 0x04): #RST zombie
			#SYN al target del zombie
			port = 1
			while port < 1024:
				#Enviar Primer SA al zombie
				resp1 = sr1(ip1/tcp1, timeout = 1, verbose=0)
				ipCount = resp1.id #obtenga 
				#Enviar S del zombie al target
				resp2 = send(IP(dst = sys.argv[3], src = sys.argv[2])/TCP(dport = port, flags="S"), verbose=0)
				#envio SA al zombie
				resp3 = sr1(IP(dst = sys.argv[2])/TCP(dport = port, flags="SA"), timeout = 1, verbose=0)
				if (str(type(resp1))=="<type 'NoneType'>"):
					Filtered = Filtered +1
				elif(resp1.haslayer(TCP)):
					if (resp1.getlayer(TCP).flags == 0x04): #RST zombie
						if (resp3.id -2 == ipCount):
							print("Puerto" + str(port) + "abierto")
				else:
					Filtered = Filtered +1
				port = port+1
	print("Puertos Cerrados/filtrados:  "+  str(Filtered))
				

def opciones():
	if sys.argv[1] == "-sT":
		return TCP_Connect()
	if sys.argv[1] == "-sS":
		return TCP_SYN()
	if sys.argv[1] == "-sA":
		return TCP_ACK()
	if sys.argv[1] == "-sF":
		return TCP_FIN()	
	if sys.argv[1] == "-sU":
		return TCP_UDP()
	if sys.argv[1] == "-sI":
		return TCP_IDLE_SCAN()								
		
	else:
		print ("Error - opción inválida")
		print ("---help---")
		print ("Para ayuda digite:my_nmap -h")
		sys.exit(1)

		
def main():
	print ("Bienvenido a my_nmap")
	revisarEntrada()
	opciones()



main() #llamado a función main()
	

