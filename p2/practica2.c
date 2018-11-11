/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira, Javier Ramos
 2018 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define BREAKLOOP -2
#define NO_FILTER 0
#define NO_LIMIT -1
#define TCP 2
#define UDP 3
#define NO_IPV4 5
#define NO_PRIMER_FRAG 6
#define PROT_NO_CONOCIDO 7
void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);



void handleSignal(int nsignal);
int analizar_ethernet(const uint8_t *pack); 
int analizar_ip(const uint8_t *pack, uint8_t *protocolo, uint8_t *ip_origen, uint8_t *ip_destino);
void version_longitud(uint8_t *aux, uint8_t *version, uint8_t *longitud_cabecera);
void posicion_ip(uint16_t * aux_pos, uint16_t *posicion);
int comprobar_filtro(uint8_t *dir_origen, uint8_t *ip_origen);




pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

void handleSignal(int nsignal)
{
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado\n");
	pcap_breakloop(descr);
}

int main(int argc, char **argv)
{
	

	char errbuf[PCAP_ERRBUF_SIZE];
	
	int long_index = 0, retorno = 0;
	char opt;
	
	(void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc == 1) {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			printf("Descomente el código para leer y abrir de una interfaz\n");
			exit(ERROR);

		
			//if ( (descr = ??(optarg, ??, ??, ??, errbuf)) == NULL){
			//	printf("Error: ??(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
			//	exit(ERROR);
			//}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	//if(ipsrc_filter[0]!=0)
	printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	//if(ipdst_filter[0]!=0)
	printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	retorno=pcap_loop(descr,NO_LIMIT,analizar_paquete,NULL);
	switch(retorno)	{
		case OK:
			printf("Traza leída\n");
			break;
		case PACK_ERR: 
			printf("Error leyendo paquetes\n");
			break;
		case BREAKLOOP: 
			printf("pcap_breakloop llamado\n");
			break;
	}
	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}



void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack){
	(void)user;
	uint8_t protocolo = 0;
	printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
	contador++;
	if(analizar_ethernet(pack) == OK){ /* es IP*/

		pack += ETH_HLEN;
		int salida_ip = analizar_ip(pack, &protocolo, ipsrc_filter, ipdst_filter);
		if(salida_ip == NO_IPV4){
			printf("No es un paquete Ipv4. Se termina su procesado.\n\n");
		}
		else if(salida_ip == NO_PRIMER_FRAG){
			printf("El paquete IP leido no es el primer fragmento. Se termina su procesado.\n\n");
		}
		else if (salida_ip == ERROR){
			printf("El protocolo no es TCP ni UDP. Se termina su procesado.\n\n");
		}
		else if(salida_ip == ERROR){
			printf("Se termina su procesado.\n\n");
		}
		else{ /* es UDP o TCP */
			pack += salida_ip;
			printf("FUNICONA\n\n");
		}
	}else{
		printf("NO ES IP. No se sigue procesando el paquete.\n\n");
	}
	
}

/*
 * analiza el nivel de enlace, imprimiendo destino y origen. 
 * Tras esto comprueba is el tipo de protocolo es Ipv4. 
 * Devuelve OK si es Ipv4, Error en caso contrario.
 */
int analizar_ethernet(const uint8_t *pack){
	uint16_t es_ipv4 = 0x800, tipo_protocolo=0;
	int i = 0;

	/* direccion destino */
	printf("......................................................\n");
	printf("Nivel 2:\n");
	printf("Direccion ETH destino= ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}
	printf("\n");
	pack += ETH_ALEN; /* sumamos para pasar a la direccion origen */

	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);

	/* direccion origen*/
	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}
	printf("\n");
	printf("......................................................\n");

	pack += ETH_ALEN; /* sumamos para ver el tipo de protocolo */
	memcpy(&tipo_protocolo, pack, sizeof(uint16_t));
	tipo_protocolo = ntohs(tipo_protocolo); /* pasamos los datos de network a host */

	if(tipo_protocolo == es_ipv4){ /* comprobamos si es ipv4*/
		return OK;
	}
	return ERROR; /* no es ipv4 */
}

int analizar_ip(const uint8_t *pack, uint8_t *protocolo, uint8_t *ip_origen, uint8_t *ip_destino){
	uint8_t version, aux, longitud_cabecera, tiempo_vida, dir_origen[IP_ALEN], dir_destino[IP_ALEN];
	uint16_t aux_pos, posicion, longitud_total;
	int i;

	printf("------------------------------------------------------\n");
	printf("Nivel 3:\n");
	
	memcpy(&aux, pack, sizeof(uint8_t));
	pack += sizeof(uint8_t);
	pack += sizeof(uint8_t); /* saltamos el campo 'tipo servicio' y nos posicionamos en long total */
	memcpy(&longitud_total, pack, sizeof(uint16_t));
	pack += sizeof(uint16_t);

	longitud_total = ntohs(longitud_total);
	version_longitud(&aux, &version, &longitud_cabecera);
	printf("Version: %"PRIu8"\nLongitud de cabecera: %02x\nLongitud total: %"PRIu16"\n", version, longitud_cabecera, longitud_total);
	if(version != 4){ /* no es ipv4 */
		printf("------------------------------------------------------\n");
		return NO_IPV4;
	}

	pack += sizeof(uint16_t); /* saltamos identificacion (estamos en flags)*/
	
	memcpy(&aux_pos, pack, sizeof(uint16_t));
	posicion_ip(&aux_pos, &posicion);
	pack += sizeof(uint16_t); /* saltamos flags-posicion*/
	printf("Posicion: %"PRIu16"\n", posicion);
	if(posicion != 0){
		printf("------------------------------------------------------\n");
		return NO_PRIMER_FRAG;
	}
	memcpy(&tiempo_vida, pack, sizeof(uint8_t)); /* tiempo de vida */
	pack += sizeof(uint8_t);
	printf("Tiempo de vida: %"PRIu8"\n", tiempo_vida);

	/* copiamos el protocolo en el puntero pasado por argumento a la funcion */
	memcpy(protocolo, pack, sizeof(uint8_t)); /* protocolo */
	pack += sizeof(uint8_t);
	printf("Protocolo: ");
	if (*protocolo == 0x06){
		printf("TCP\n");
	}else if ((*protocolo) == 0x11){
		printf("UDP\n");
	}else{printf("No conocido.\n");
		printf("------------------------------------------------------\n");
		return PROT_NO_CONOCIDO;
	}

	pack += sizeof(uint16_t); /* saltamos  suma de control cabecera */

	printf("Direcion origen: ");
	for(i=0; i<IP_ALEN; i++){
		memcpy(dir_origen+i, pack, sizeof(uint8_t));
		pack += sizeof(uint8_t);
		if(i != 3){
			printf("%"PRIu8".", dir_origen[i]);
		}else{
			printf("%"PRIu8"\n", dir_origen[i]);
		}
	}
	if(comprobar_filtro(dir_origen, ip_origen) == ERROR){
		printf("El filtro de origen introducido no coincide.\n");
		printf("------------------------------------------------------\n");
		return ERROR;
	}

	printf("Direccion destino: ");
	for(i=0; i<IP_ALEN; i++){
		memcpy(dir_destino+i, pack, sizeof(uint8_t));
		pack += sizeof(uint8_t);
		if(i != 3){
			printf("%"PRIu8".", dir_destino[i]);
		}else{
			printf("%"PRIu8"\n", dir_destino[i]);
		}
	}
	if(comprobar_filtro(dir_destino, ip_destino) == ERROR){
		printf("El filtro de destino introducido no coincide.\n");
		printf("------------------------------------------------------\n");
		return ERROR;
	}


	printf("------------------------------------------------------\n");
	return longitud_cabecera*4;
}

void version_longitud(uint8_t *aux, uint8_t *version, uint8_t *longitud_cabecera){
	/* aplicamos una mascara para conseguir los 4 primeros bit donde esta la version */
	uint8_t aux2 = ((*aux) & 0xF0) >> 4;
	memcpy(version, &aux2, sizeof(uint8_t));

	/* mascara para conseguir los siguientes 4 bits - longitud cabecera */
	aux2 = (*aux) & 0X0F;
	memcpy(longitud_cabecera, &aux2, sizeof(uint8_t));
}

void posicion_ip(uint16_t * aux_pos, uint16_t *posicion){
	/* mascara para no leer el valor que hay en flags (3 bits)*/
	uint16_t aux2 = (*aux_pos) & 0x1FFF; 
	aux2 = ntohs(aux2);
	memcpy(posicion, &aux2, sizeof(uint16_t));

}


int comprobar_filtro(uint8_t *dir_origen, uint8_t *ip_origen){
	for(int i=0; i<IP_ALEN; i++){
		if(ip_origen[i] && ip_origen[i] != dir_origen[i]){
			return ERROR;
		}
	}
	return OK;
}