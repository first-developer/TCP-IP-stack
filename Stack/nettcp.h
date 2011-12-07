/*
 * Definitions for IP protocol implementation
 */

////
// Constants
////

#define TCP_ISN                   123456789
#define MAX_BYTES_BY_ROW          16
#define TCP_OPTION_TYPE_EOF       0
#define TCP_OPTION_TYPE_NOP       1
#define TCP_OPTION_TYPE_MSS       2
#define TCP_NO_OPTION             0  // default value for no option length


// TCP connection state
// ----------------------------------------
#define   TCP_CLOSED_STATE          1
#define   TCP_LISTEN_STATE          2
#define   TCP_SYN_SENT_STATE        3
#define   TCP_SYN_RECEIVED_STATE    4 
#define   TCP_ESTABLISHED_STATE     5   
#define   TCP_CLOSE_WAIT_STATE      6
#define   TCP_CLOSE_TIME_WAIT       7
#define   TCP_CLOSING_WAIT_STATE    8
#define   TCP_FIN_WAIT_1_STATE      9
#define   TCP_FIN_WAIT_2_STATE      10
#define   TCP_LAST_ACK_STATE        11

// TCP FLAGS
// ----------------------------------------
#define   CWR     'c'    
#define   ECE     'e'    
#define   URG     'u'    
#define   ACK     'a'    
#define   PSH     'p'    
#define   RST     'r'    
#define   SYN     's'    
#define   FIN     'f'    




////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned short int  tcph_source;            /* port source */
  unsigned short int  tcph_target;            /* port destination */
  uint32_t            tcph_seq;                /* numero de sequence */
  uint32_t            tcph_ack;               /* numero d'acquittement */
  unsigned char       tcph_offset:4,          /* l'offset: position des données en mots de 32 bits */
                      tcph_reserved:4;        /* le champ reserved  */
  unsigned char       tcph_flags_CWR:1,       //
                      tcph_flags_ECE:1,       //
                      tcph_flags_URG:1,       //   
                      tcph_flags_ACK:1,       //    TCP HEADER FLAGS (8 bits)
                      tcph_flags_PSH:1,       //
                      tcph_flags_RST:1,       //
                      tcph_flags_SYN:1,       //
                      tcph_flags_FIN:1;       //
  unsigned short int  tcph_window;            /* Taille de la fenetre */
  unsigned short int  tcph_checksum;          /* la somme de controle */
  unsigned short int  tcph_urgptr;            /* Pointeur urgent */
  unsigned char       options[1];
} TCP_header_fields;


typedef struct{
  unsigned char       tcpo_type;              /* identificateur du type de l'option  */
  unsigned char       tcpo_length;            /* options tcpo_length */ 
  unsigned short int  tcpo_data;              /* data option  */
  unsigned char       data[1];                /* tcp data */
  } TCP_options_fields;


#pragma pack(0)

////
// Les accesseurs et mutateurs 
////
#define TCP_get_option_MSS_length(tcp_options)  (((tcp_options->data)>>4)&0xff);


// TODO: generate_isn() : unit32_t    Generateur de numeros de sequence initial pour 
//                                    gérer l'unicité des numéro de séquences.


#pragma pack()

////
// Prototypes
////

#ifdef VERBOSE
void displayTCPPacket(FILE *output,TCP_header_fields *tcph,int size);
#endif
unsigned char tcpDecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char tcpSendPacket(EventsEvent *event,EventsSelector *selector);

void init_tcph_flags( TCP_header_fields* tcph);                       // puts all flags to 0
void display_tcph_flags(TCP_header_fields* tcph);                     // show tcp header flags
void put_tcph_flag_on( TCP_header_fields* tcph, unsigned char flag);  // set the flag to 1 depends on our needs
void put_tcph_flag_off( TCP_header_fields* tcph, unsigned char flag); // set the flag to 0 depends on our needs
void display_tcp_options(FILE *output, TCP_options_fields *tcpo);     // Display content of tcp option fields
