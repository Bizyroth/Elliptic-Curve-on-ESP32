#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "ecc.h"
#include "freertos/semphr.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "lwip/tcp.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <errno.h>
#include "bmp180.h"

#define WIFI_SSID "AndroidHotspot1443"
#define WIFI_PASS "9FNb{Jsr68"

#define TIMER_KEY_GENERATION 	500000                   //interval between each symetric key generation (in ms)
#define TIMER_MESURE     		3000					 //interval between each sample (in ms)
#define BUFF_SIZE_MAX			240						 //size max in bit of the buffer to send
#define MSG_SIZE				24						 //size of one message to put in the buffer
#define TEMP_SIZE				8
#define PRESS_SIZE				8

#define IP_SERVER "192.168.43.186"


// Event group
static EventGroupHandle_t wifi_event_group;
const int CONNECTED_BIT = BIT0;
//Allow to generate the first symetric key before starting sampling
int FIRST_KEY=0;

//global variable shared between the different task
uint8_t key[32];
uint8_t extern_pubkey[64];
uint8_t wraped_key[132];
SemaphoreHandle_t xMutex=NULL;


// Wifi event handler
static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
	case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
	case SYSTEM_EVENT_STA_DISCONNECTED:
		xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
	default:
        break;
    }
	return ESP_OK;
}

/*
 * \brief							Fullfill global variable wrapped_buffer with iv || tag || encrypted_buffer
 *
 * \param	encrypted_buffer		The encrypted buffer to wrap before sending it
 * 			iv						Iv used for encryption
 * 			tag						Tag computed by the encryption
 * 			wrapped_buffer			The buffer to fullfill
 * 			wrap_size
 */
void wrap_buffer(uint8_t * encrypted_buffer, unsigned buffer_size,uint8_t * iv, uint8_t * tag,uint8_t * wrapped_buffer){
	memcpy(wrapped_buffer,iv,IV_SIZE);
	memcpy(wrapped_buffer+IV_SIZE,tag,TAG_SIZE);
	memcpy(wrapped_buffer+IV_SIZE+TAG_SIZE,encrypted_buffer,buffer_size);
}


/*
 * \brief							Fullfill global variable key with a AESGCM symetric key
 *
 */
void symetric_generation(){
	uint8_t ephemeral_pubkey[PUB_KEY_SIZE];
	int r=0;
	if((r=symetric_key_generation(key,extern_pubkey,ephemeral_pubkey))!=1){
		printf("error during symetric generation: %d\n",r);
	}
	return;
}

/*
 * \brief							Encrypt the global variable key with ECIES cipher before sending it to the receiver
 * 									Send a wrapped key of the form id_curve(3) || length(public_key) || ephemeral pubkey || tag || iv || ciphertext
 *
 * \param 		param				Must be a pointer of the socket to send wrapped key
 *
 */
void ecc_key_task(void * param){
	int * sock = (int *)param;
	for(;;){

		if(xSemaphoreTake(xMutex,( TickType_t ) 0)==pdTRUE){

			memset(key,0,32);
			memset(wraped_key,0,32+4+PUB_KEY_SIZE+TAG_SIZE+IV_SIZE);
			symetric_generation();
			xSemaphoreGive(xMutex);

			ECIES_encrypt_key(key,32,extern_pubkey,wraped_key);
			send(*sock,wraped_key,32+4+PUB_KEY_SIZE+TAG_SIZE+IV_SIZE,0);
			FIRST_KEY=1;
			memset(wraped_key,0,32+4+PUB_KEY_SIZE+TAG_SIZE+IV_SIZE);
			vTaskDelay(TIMER_KEY_GENERATION / portTICK_RATE_MS);
		}else{
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	}
}

void echantillonage_task(void * param){
	while(FIRST_KEY!=1){
		//wait for the first symetric key to be computed and sent
	}
	int i=0,j=0,k=0;
	int * sock=(int *) param;
	uint8_t buffer[BUFF_SIZE_MAX];
	uint8_t random[MSG_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];
	uint8_t encrypted_buffer[BUFF_SIZE_MAX];
	uint8_t wraped_buffer[BUFF_SIZE_MAX+IV_SIZE+TAG_SIZE];
	uint8_t local_key[32];
	float temp;
	uint8_t temp_char[TEMP_SIZE];
	uint8_t press_char[PRESS_SIZE];
	uint8_t timestamp[8];
	uint32_t press;
	memcpy(local_key,key,32);
	for(;;){
		//Symetric key computation is passive, we fulfill the buffer and send it when BUFF_SIZE_MAX bytes are written
		if(xSemaphoreTake(xMutex,( TickType_t ) 0)==pdTRUE){

			if(i<BUFF_SIZE_MAX){
				random32(random,MSG_SIZE);
				echantillon(&temp,&press);
				snprintf((char *)timestamp,8,"%0ld",time(NULL));
				printf("timestamp: %s\n",timestamp);
				memcpy(buffer+i,timestamp,8);

				snprintf((char *)temp_char,TEMP_SIZE,"%.8f",temp);
				memcpy(buffer+i+8,temp_char,TEMP_SIZE);
				for(j=0;j<32;j+=8){
					press_char[k]=(press>>j)&0xFF;
					k++;
				}
				k=0;
				memcpy(buffer+i+TEMP_SIZE+8,press_char,8);

				print_hex(buffer, TEMP_SIZE+PRESS_SIZE+8+i);
				i+=PRESS_SIZE+TEMP_SIZE+8;
			}else{
				AESGCM(buffer,BUFF_SIZE_MAX,MBEDTLS_ENCRYPT,key,iv,tag,encrypted_buffer);
				wrap_buffer(encrypted_buffer,BUFF_SIZE_MAX,iv,tag,wraped_buffer);
				send(*sock,wraped_buffer,BUFF_SIZE_MAX+IV_SIZE+TAG_SIZE,0);
				i=0;
				memset(buffer,0,BUFF_SIZE_MAX);
			}
			xSemaphoreGive(xMutex);
		//Symetric key computation is active, we send the buffer not full and wait for the new symmetric key
		}else{
			AESGCM(buffer,i,MBEDTLS_ENCRYPT,local_key,iv,tag,encrypted_buffer);
			wrap_buffer(encrypted_buffer,i,iv,tag,wraped_buffer);
			send(*sock,wraped_buffer,i+IV_SIZE+TAG_SIZE,0);
			i=0;
			memset(buffer,0,BUFF_SIZE_MAX);
			memset(local_key,0,32);
			while(xSemaphoreTake(xMutex,( TickType_t) 5)!=pdTRUE){
				//waiting for the new symmetric key
			}
			xSemaphoreGive(xMutex);
			memcpy(local_key,key,32);
		}
		//clear the temporary buffer
		memset(encrypted_buffer,0,BUFF_SIZE_MAX);
		memset(iv,0,IV_SIZE);
		memset(tag,0,TAG_SIZE);
		memset(wraped_buffer,0,BUFF_SIZE_MAX+IV_SIZE+TAG_SIZE);
		vTaskDelay(TIMER_MESURE/portTICK_RATE_MS);

	}
}

void wifi_task(void * param){
	// wait for connection
	printf("Main task: waiting for connection to the wifi network... ");
	xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, 0, 1, portMAX_DELAY);
	printf("connected!\n");
	// print the local IP address
	tcpip_adapter_ip_info_t ip_info;
	ESP_ERROR_CHECK(tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info));
	printf("IP Address:  %s\n", ip4addr_ntoa(&ip_info.ip));
	printf("Subnet mask: %s\n", ip4addr_ntoa(&ip_info.netmask));
	printf("Gateway:     %s\n", ip4addr_ntoa(&ip_info.gw));

	vTaskDelete(NULL);
}



void app_main(){
	int sock;
	int rc;
	uECC_set_rng(&random32);
	uint8_t recv_key[PUB_KEY_SIZE+1];
	xMutex=xSemaphoreCreateMutex();

	/*Sensor configuration*/

	i2c_config_t conf;
	conf.mode = I2C_MODE_MASTER;
	conf.sda_io_num = 22;
	conf.scl_io_num = 23;
	conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
	conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
	conf.master.clk_speed = 100000;

	i2c_param_config(I2C_NUM_0, &conf);

	i2c_driver_install(I2C_NUM_0, I2C_MODE_MASTER, 0, 0, 0);


	/*Wifi connection*/

	// disable the default wifi logging
	esp_log_level_set("wifi", ESP_LOG_NONE);

	// create the event group to handle wifi events
	wifi_event_group = xEventGroupCreate();

	// initialize the tcp stack
	tcpip_adapter_init();

	// initialize the wifi event handler
	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

	// initialize the wifi stack in STAtion mode with config in RAM
	wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

	// configure the wifi connection and start the interface
	wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    printf("Connecting to %s\n", WIFI_SSID);
    //launch wifi connection
    xTaskCreatePinnedToCore(&wifi_task, "wifi_task", 2048, NULL,5,NULL,0);
	xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, 0, 1, portMAX_DELAY);



	//FIN WIFI
    if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
    	printf("Error during socket creation\n");
    }
    struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
    if((inet_pton(AF_INET,IP_SERVER,&serverAddress.sin_addr.s_addr))!=1){
    	printf("Error during addr conversion\n");
    }
    serverAddress.sin_port=htons(1234);
    errno=0;
     if((rc=connect(sock,(struct sockaddr *)&serverAddress,sizeof(struct sockaddr_in)))<0){
    	 printf("Error during connection to server\n");
    	 printf("error code: %s\n",strerror(errno));
    	 errno=0;
     }
     if((rc=recv(sock,recv_key,PUB_KEY_SIZE+1,0))<0){
    	 printf("probleme reception cle\n");
    	 printf("error code: %s\n",strerror(errno));
    	 errno=0;
     }

     memcpy(extern_pubkey,recv_key+1,PUB_KEY_SIZE);

     if((rc=uECC_valid_public_key(extern_pubkey, CURVE))==0){
    	 printf("Invalid extern pubkey\n");
     }

	xTaskCreatePinnedToCore(&ecc_key_task, "ecc_key_task", 4096, &sock, 5, NULL,0);
	xTaskCreatePinnedToCore(&echantillonage_task, "echantillonage", 4096, &sock, 5, NULL,1);
}


