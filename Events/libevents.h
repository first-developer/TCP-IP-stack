/*
 * Common definitions for handling events
 */

////
// Constants
////
#define EVENTS_ONDESCRIPTOR		0
#define EVENTS_ONTRIGGER		1
#define EVENTS_ONTIMER			2

#define EVENTS_BLOCK_SIZE		5
#define EVENTS_ACTIONS_BLOCK_SIZE	5
#define EVENTS_SELECTORS_BLOCK_SIZE	5

////
// Structures
////
typedef union{
  int descriptor;
  long int timeout;
  } EventsSelectorsUnion;

typedef struct{
  unsigned char rank;
  unsigned char type;
  EventsSelectorsUnion selector;
  void *data_this;
  } EventsSelector;

typedef struct{
  int identity;
  short int priority;
  void *data_init;
  EventsSelector *selectors;
  int selectors_nb;
  int selectors_nb_allocated;
  struct _EventsAction *actions;
  int actions_nb;
  int actions_nb_allocated;
  } EventsEvent;

typedef struct _EventsAction{
  short int level;
  unsigned char (*action)(EventsEvent *,EventsSelector *);
  } EventsAction;

typedef struct{
  int events_nb;
  int events_nb_allocated;
  EventsEvent *events;
  } EventsStruct;

////
// Prototypes
////
int eventsCreate(int priority,void *data);
void eventsRemove(int identity);
int eventsAssociateDescriptor(int identity,int descriptor,void *data);
int eventsTrigger(int identity,void *data);
int eventsSchedule(int identity,long timeout,void *data);
int eventsAddAction(int identity,
                    unsigned char (*handler)(EventsEvent *,EventsSelector *),
                    int level);
void eventsScan(void);
