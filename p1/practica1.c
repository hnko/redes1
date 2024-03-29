
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <math.h>

#define ERROR 1
#define OK 0

#define PROMISC 0
#define TIMEOUT_LIMIT 100

#define SUM_SECS 1800 /*30 min in seconds */

#define INFINITE -1
#define ETH_FRAME_MAX 1514	// Tamano maximo trama ethernet

#define RED     "\x1b[31m"
#define RESET   "\x1b[0m"

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;
int p_count=0, offline=0;
uint8_t to_print=0;

void handle(int nsignal){
	printf("Control C pulsado\n");
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);

	printf(RED "\n\n>>> The total of packets captured is: %d." RESET "\n", p_count);

	exit(OK);
 }
  
void callback(uint8_t*usuario,  const struct pcap_pkthdr* header,  const uint8_t* body){
	struct pcap_pkthdr* header_aux;
	header_aux = (struct pcap_pkthdr*) header;
	p_count++;
	header_aux->ts.tv_sec += SUM_SECS;
	if(!offline){
		printf("Packet %d captured at %s\n",p_count, ctime((const time_t*)&(header_aux->ts.tv_sec)));
		if(pdumper){
	 		pcap_dump((uint8_t *)pdumper,header_aux,body);
		}
	}
	uint8_t i;
	to_print = fmin(to_print, header->caplen); /* for prevent SIGSEGV */

	for( i=0; i<to_print; i++){
		printf("%02x ", body[i]);
	}
	printf("\n");

}

int main(int argc, char **argv){
	int ret, flag_free=0;
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	char file_name[256];
	u_char *user=NULL;
	struct timeval time;

	/* check the input parameters */
	if(argc < 3 || argc > 4){
		printf("For excecute you have two options:\n"
				"\t<-f> (if you want to find a device) <-nf> if you want eth0)\n"
				"\t<number_of_bytes_to_be_printed>\n"
				"\t<number_of_bytes_to_be_printed> <file_name>\n");
		exit(ERROR);
	}
	if(atoi(argv[2]) < 1){
		printf("The number of bytes must be 1 or more.\n");
		exit(ERROR);
	}
	/* check if we need to find a device or use eth0 */
	if(strcmp(argv[1], "-f") == 0){
		if((device = pcap_lookupdev(errbuf))==NULL){
			printf("Erro finding the device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}else{
		flag_free = 1;
		device = malloc(sizeof(char)*strlen("eth0")+1);
		strcpy(device, "eth0");
	}
	/* get the number of bytes to capture from the input parameters */
	to_print = (atoi(argv[2]) > ETH_FRAME_MAX) ? ETH_FRAME_MAX : atoi(argv[2]);

	/* signal ctrl+C */
	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}
	offline = (argc == 4) ? 1 : 0;
	/* check which option the user wants */
	if(!offline){ /* capture in live */
		if ((descr = pcap_open_live(device,ETH_FRAME_MAX,PROMISC,TIMEOUT_LIMIT, errbuf)) == NULL){
			printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			exit(ERROR);
		}

		//Para volcado de traza
		/* linktype and the max size packet we want to save */
		descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
		if (!descr2){
			printf("Error al abrir el dump.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		gettimeofday(&time,NULL);
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);
		pdumper=pcap_dump_open(descr2,file_name);
		if(!pdumper){
			printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
			exit(ERROR);
		}
	}else{ /* read from a file */
		if((descr = pcap_open_offline(argv[3], errbuf)) == NULL){
			printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			exit(ERROR);
		}
      	
  	}
  	if(flag_free){
  		free(device);	
  	}
	//for the packet count we use a global variable
	ret = pcap_loop (descr, INFINITE, callback, (uint8_t*)&user);
	if(ret == -1){ 		//En caso de error
		printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
		if(!offline){
			pcap_close(descr2);
			pcap_dump_close(pdumper);
		}
		pcap_close(descr);
		exit(ERROR);
	}
	else if(ret==-2){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
		printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__); 
	}
	else if(ret == 0){
		printf("No mas paquetes o limite superado %s %d.\n",__FILE__,__LINE__);
	}
	
	if(!offline){/* close if we were in live mode */
		pcap_dump_close(pdumper);
		pcap_close(descr2);
	}

	pcap_close(descr);

	return OK;
}
