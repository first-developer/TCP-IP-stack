/*
 * Common code for handling events
 */

////
// Include files
////
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

#include "libevents.h"

////
// Macros
////
#define printTabs(output,nb) { int i; for(i=0;i<nb;i++) fprintf(output," "); }

////
// Global variables
////

static EventsStruct *events=NULL;

////
// Private prototypes
////
static EventsStruct *eventsInit(void);
static int eventsExpand(EventsStruct *events);
static int eventsSortEvents(const void *v1,const void *v2);
static EventsEvent *eventsGetEventById(int identity);
static void eventsActionsInit(EventsEvent *event);
static int eventsActionsExpand(EventsEvent *event);
static int eventsSortActions(const void *v1,const void *v2);
static void eventsSelectorsInit(EventsEvent *event);
static int eventsSelectorsExpand(EventsEvent *event);
static EventsSelector *eventsAddSelector(int identity,int type,
                                         void *data);
static void eventsRemoveSelector(EventsEvent *event,EventsSelector *selector,
                                 unsigned removeOnDescriptor);
static void eventsHandle(EventsEvent *event,EventsSelector *selector);
static fd_set eventsBuildSet(int *max,int *nb);
static struct timeval eventsNextTimer(void);
static void eventsUpdateTimers(long int delta);
#ifdef DEBUG_EVENTS
static void eventsDisplayEvent(FILE *output,short int tabs,EventsEvent *event);
static void eventsDisplayAction(FILE *output,short int tabs,
                                EventsAction *action);
static void eventsDisplaySelector(FILE *output,short int tabs,
                                  EventsSelector *selector);
#endif

////
// Functions
////

//
// Initialize events structure
//
static EventsStruct *eventsInit(void){
EventsStruct *result=(EventsStruct *)malloc(sizeof(EventsStruct));
result->events=(EventsEvent *)malloc(EVENTS_BLOCK_SIZE*sizeof(EventsEvent));
result->events_nb_allocated=EVENTS_BLOCK_SIZE;
result->events_nb=0;
return result;
}

//
// Add space to events structure
//
static int eventsExpand(EventsStruct *events){
events->events_nb_allocated += EVENTS_BLOCK_SIZE;
events->events=(EventsEvent *)
  realloc(events->events,events->events_nb_allocated*sizeof(EventsEvent));
return (events->events==NULL)?-1:0;
}

//
// Sort events
//
static int eventsSortEvents(const void *v1,const void *v2){
EventsEvent *e1=(EventsEvent *)v1;
EventsEvent *e2=(EventsEvent *)v2;
return (e1->priority-e2->priority);
}

//
// Get an event by its identity
//
static EventsEvent *eventsGetEventById(int identity){
int i;
for(i=0;i<events->events_nb;i++)
  if(events->events[i].identity==identity) break;
if(i<events->events_nb) return events->events+i;
return NULL;
}

//
// Create an event
//
int eventsCreate(int priority,void *data){
if(events==NULL) events=eventsInit();
if(events->events_nb>=events->events_nb_allocated)
  if(eventsExpand(events)<0) return -1;
EventsEvent *event=events->events+events->events_nb;
event->identity=events->events_nb;
event->priority=priority;
event->data_init=data;
event->actions=NULL;
event->actions_nb=0;
event->actions_nb_allocated=0;
event->selectors=NULL;
event->selectors_nb=0;
event->selectors_nb_allocated=0;
events->events_nb++;
#ifdef DEBUG_EVENTS
fprintf(stderr,"New event (total=%d):\n",events->events_nb);
eventsDisplayEvent(stderr,2,event);
#endif
qsort(events->events,events->events_nb,sizeof(EventsEvent),eventsSortEvents);
return events->events_nb-1;
}

//
// Remove an event
//
void eventsRemove(int identity){
EventsEvent *event=eventsGetEventById(identity);
if(event!=NULL){
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Removing event #%d:\n",identity);
  eventsDisplayEvent(stderr,2,event);
#endif
  if(events->events_nb>1)
    *event=events->events[events->events_nb-1];
  if(event->actions!=NULL) free(event->actions);
  if(event->selectors!=NULL) free(event->selectors);
  events->events_nb--;
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Now %d remaining events.\n",events->events_nb);
#endif
  if(events->events_nb==0){
     free(events->events);
     free(events);
     events=NULL;
     }
  }
else{
#ifdef DEBUG_EVENTS
fprintf(stderr,"Cannot remove event of id #%d!\n",identity);
#endif
 }
}

//
// Display an event
//
#ifdef DEBUG_EVENTS
static void eventsDisplayEvent(FILE *output,short int tabs,EventsEvent *event){
int i;
printTabs(output,tabs);
fprintf(output,"id: %d, priority: %d, data: %x\n",
        event->identity,event->priority,(unsigned int)event->data_init);
fprintf(output,"selectors: %d/%d\n",
        event->selectors_nb,event->selectors_nb_allocated);
for(i=0;i<event->selectors_nb;i++){
  printTabs(output,tabs); fprintf(output,"selector #%d\n",i);
  eventsDisplaySelector(output,tabs+2,event->selectors+i);
  }
fprintf(output,"actions: %d/%d\n",
        event->actions_nb,event->actions_nb_allocated);
for(i=0;i<event->actions_nb;i++){
  printTabs(output,tabs); fprintf(output,"action #%d\n",i);
  eventsDisplayAction(output,tabs+2,event->actions+i);
  }
}
#endif

//
// Initialize selectors structure
//
static void eventsSelectorsInit(EventsEvent *event){
event->selectors=(EventsSelector *)
  malloc(EVENTS_SELECTORS_BLOCK_SIZE*sizeof(EventsSelector));
event->selectors_nb_allocated=EVENTS_SELECTORS_BLOCK_SIZE;
event->selectors_nb=0;
}

//
// Add space to selectors structure
//
static int eventsSelectorsExpand(EventsEvent *event){
event->selectors_nb_allocated += EVENTS_SELECTORS_BLOCK_SIZE;
event->selectors=(EventsSelector *)
  realloc(event->selectors,event->selectors_nb_allocated*sizeof(EventsSelector));
return (event->selectors==NULL)?-1:0;
}

//
// Add selector to an event
//
static EventsSelector *eventsAddSelector(int identity,int type,
                                         void *data){
EventsEvent *event=eventsGetEventById(identity);
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding selector to event:\n");
eventsDisplayEvent(stderr,2,event);
#endif
if(event->selectors==NULL) eventsSelectorsInit(event);
if(event->selectors_nb>=event->selectors_nb_allocated)
  if(eventsSelectorsExpand(event)<0) return NULL;
EventsSelector *selector=event->selectors+event->selectors_nb;
int i,rank=0;
for(i=0;i<event->selectors_nb;i++) 
  if(event->selectors[i].rank>rank) rank=event->selectors[i].rank;
selector->rank=rank;
selector->type=type;
selector->data_this=data;
event->selectors_nb++;
return selector;
}

//
// Remove selector from an event
//
static void eventsRemoveSelector(EventsEvent *event,EventsSelector *selector,
                                 unsigned removeOnDescriptor){
int i;
if(selector->type==EVENTS_ONDESCRIPTOR && removeOnDescriptor==0) return;
for(i=0;i<event->selectors_nb;i++)
  if(event->selectors+i==selector){
#ifdef DEBUG_EVENTS
    fprintf(stderr,"Removing selector #%d from event:\n",i);
    eventsDisplayEvent(stderr,2,event);
#endif
    int j,rank=event->selectors[i].rank;
    for(j=0;j<event->selectors_nb;j++) 
      if(event->selectors[j].rank>rank) event->selectors[j].rank--;
    if(event->selectors_nb>1)
      event->selectors[i]=event->selectors[event->selectors_nb-1];
    event->selectors_nb--;
#ifdef DEBUG_EVENTS
    fprintf(stderr,"Event after removal:\n");
    eventsDisplayEvent(stderr,2,event);
#endif
    return;
    }
#ifdef DEBUG_EVENTS
fprintf(stderr,"Trying to remove inexistant selector!\n");
#endif
}

//
// Display a selector
//
#ifdef DEBUG_EVENTS
static void eventsDisplaySelector(FILE *output,short int tabs,EventsSelector *selector){
printTabs(output,tabs);
fprintf(output,"type: ");
switch(selector->type){
  case EVENTS_ONDESCRIPTOR:
    fprintf(output,"descriptor (fd=%d)",selector->selector.descriptor);
    break;
  case EVENTS_ONTRIGGER:
    fprintf(output,"trigger");
    break;
  case EVENTS_ONTIMER:
    fprintf(output,"timer (timeout=%ld)",selector->selector.timeout);
    break;
  }
fprintf(output,"\n");
printTabs(output,tabs);
fprintf(output,"data: %x\n",(unsigned int)selector->data_this);
}
#endif

//
// Associate a file descriptor to an event
// (should be handled when activity detected)
//
int eventsAssociateDescriptor(int identity,int descriptor,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding descriptor selector (descriptor=%d).\n",descriptor);
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONDESCRIPTOR,data);
if(selector==NULL) return -1;
selector->selector.descriptor=descriptor;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Trigger an event (should be handled as soon as possible)
//
int eventsTrigger(int identity,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding trigger selector.\n");
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONTRIGGER,data);
if(selector==NULL) return -1;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Schedule event (should be handled when timeout expires)
//
int eventsSchedule(int identity,long timeout,void *data){
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding timeout selector (timeout=%ld).\n",timeout);
#endif
EventsSelector *selector=eventsAddSelector(identity,EVENTS_ONTIMER,data);
if(selector==NULL) return -1;
selector->selector.timeout=timeout;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after selector insertion:\n");
eventsDisplayEvent(stderr,2,eventsGetEventById(identity));
#endif
return 0;
}

//
// Initialize actions structure
//
static void eventsActionsInit(EventsEvent *event){
event->actions=(EventsAction *)malloc(EVENTS_ACTIONS_BLOCK_SIZE*sizeof(EventsAction));
event->actions_nb_allocated=EVENTS_ACTIONS_BLOCK_SIZE;
event->actions_nb=0;
}

//
// Add space to events structure
//
static int eventsActionsExpand(EventsEvent *event){
event->actions_nb_allocated += EVENTS_ACTIONS_BLOCK_SIZE;
event->actions=(EventsAction *)realloc(event->actions,event->actions_nb_allocated*sizeof(EventsAction));
return (event->actions==NULL)?-1:0;
}

//
// Sort actions
//
static int eventsSortActions(const void *v1,const void *v2){
EventsAction *a1=(EventsAction *)v1;
EventsAction *a2=(EventsAction *)v2;
return (a1->level-a2->level);
}

//
// Add action function to an event
//
int eventsAddAction(int identity,
                    unsigned char (*handler)(EventsEvent *,EventsSelector *),
                    int level){
EventsEvent *event=eventsGetEventById(identity);
#ifdef DEBUG_EVENTS
fprintf(stderr,"Adding action to event:\n");
eventsDisplayEvent(stderr,2,event);
#endif
if(event->actions==NULL) eventsActionsInit(event);
if(event->actions_nb>=event->actions_nb_allocated)
  if(eventsActionsExpand(event)<0) return -1;
EventsAction *action=event->actions+event->actions_nb;
action->level=level;
action->action=handler;
event->actions_nb++;
qsort(event->actions,event->actions_nb,sizeof(EventsAction),eventsSortActions);
#ifdef DEBUG_EVENTS
fprintf(stderr,"Event after action insertion:\n");
eventsDisplayEvent(stderr,2,event);
#endif
return 0;
}

//
// Display action
//
#ifdef DEBUG_EVENTS
static void eventsDisplayAction(FILE *output,short int tabs,
                                EventsAction *action){
printTabs(output,tabs);
fprintf(output,"level: %d, action: %x\n",action->level,
               (unsigned int)action->action);
}
#endif

//
// Build a set of descriptors from events list
//
static fd_set eventsBuildSet(int *max,int *nb){
int i,j;
fd_set set;
FD_ZERO(&set);
if(max!=NULL) *max=-1;
if(nb!=NULL) *nb=0;
for(i=0;i<events->events_nb;i++){
  EventsEvent *event=events->events+i;
  for(j=0;j<event->selectors_nb;j++){
    EventsSelector *selector=event->selectors+j;
    if(selector->type==EVENTS_ONDESCRIPTOR){
      int fd=selector->selector.descriptor;
      FD_SET(fd,&set);
      if(max!=NULL && (*max)<fd) *max=fd;
      if(nb!=NULL) (*nb)++;
      }
    }
  }
return set; 
}

//
// Find the next timer to expire
//
static struct timeval eventsNextTimer(void){
int i,j;
struct timeval timer;
timer.tv_sec=-1;
for(i=0;i<events->events_nb;i++){
  EventsEvent *event=events->events+i;
  for(j=0;j<event->selectors_nb;j++){
    EventsSelector *selector=event->selectors+j;
    if(selector->type==EVENTS_ONTIMER){
      long int delta=selector->selector.timeout;
      long int sec=delta/1000000;
      long int usec=delta%1000000;
      if(timer.tv_sec<0 ||
         (timer.tv_sec>sec || (timer.tv_sec==sec && timer.tv_usec>usec)))
        { timer.tv_sec=sec; timer.tv_usec=usec; }
      }
    }
  }
return timer; 
}

//
// Update timers
//
static void eventsUpdateTimers(long int delta){
int i,j;
for(i=0;i<events->events_nb;i++){
  EventsEvent *event=events->events+i;
  for(j=0;j<event->selectors_nb;j++){
    EventsSelector *selector=event->selectors+j;
    if(selector->type==EVENTS_ONTIMER){
      long int timeout=selector->selector.timeout;
      long int new=timeout-delta;
      if(new<0) new=0;
      selector->selector.timeout=new;
      }
    }
  }
}

//
// Handle events
//
static void eventsHandle(EventsEvent *event,EventsSelector *selector){
int i;
#ifdef DEBUG_EVENTS
fprintf(stderr,"Calling action(s) for event:\n");
eventsDisplayEvent(stderr,2,event);
#endif
unsigned char status=0;
for(i=0;i<event->actions_nb;i++){
  EventsAction *action=event->actions+i;
#ifdef DEBUG_EVENTS
  fprintf(stderr,"  calling action #%d:\n",i);
  eventsDisplayAction(stderr,4,action);
#endif
  if(action->action(event,selector)!=0){ status=1; break; }
  }
eventsRemoveSelector(event,selector,status);
}

void eventsScan(void){
int i,j;
while(1){
  // Stop if there is no more event
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Scanning %d event(s).\n",events->events_nb);
#endif
  if(events->events_nb<=0) break;

  // First pass, check if an event is already in stock
  int max,nb;
  fd_set set=eventsBuildSet(&max,&nb);
  struct timeval zero;
  zero.tv_sec=0;
  zero.tv_usec=0;
  int status=0;
  if(nb>=0) status=select(max+1,&set,NULL,NULL,&zero);
  if(status<0){ perror("eventsScan.select (nowait)"); exit(-1); }
#ifdef DEBUG_EVENTS
  fprintf(stderr,"Descriptors; total=%d, actives=%d.\n",nb,status);
#endif
  EventsEvent *event;
  EventsSelector *selector;
  unsigned char stop=0;
  for(i=0;(i<events->events_nb) && (stop==0);i++){
    event=events->events+i;
    int rank_min=-1;
    int active=-1;
    for(j=0;j<event->selectors_nb;j++){
      selector=event->selectors+j;
      int rank_cur=selector->rank;
      switch(selector->type){
        case EVENTS_ONDESCRIPTOR:{
          int fd=selector->selector.descriptor;
          if((rank_min<0 || rank_cur<rank_min) && FD_ISSET(fd,&set))
            { active=j; rank_min=rank_cur; }
          }
          break;
        case EVENTS_ONTIMER:{
          long int time=selector->selector.timeout;
          if((rank_min<0 || rank_cur<rank_min) && time==0)
            { active=j; rank_min=rank_cur; }
          }
          break;
        case EVENTS_ONTRIGGER:
          if(rank_min<0 || rank_cur<rank_min)
            { active=j; rank_min=rank_cur; }
          break;
        }
      }
    if(active>=0){
      selector=event->selectors+active;
      stop=1;
#ifdef DEBUG_EVENTS
      switch(selector->type){
        case EVENTS_ONDESCRIPTOR:{
          int fd=selector->selector.descriptor;
          fprintf(stderr," selector #%d, active descriptor %d on event:\n",
                         active,fd);
          eventsDisplayEvent(stderr,4,event);
          }
          break;
        case EVENTS_ONTIMER:{
          long int time=selector->selector.timeout;
          fprintf(stderr,"  selector #%d, expired timeout %ld on event:\n",
                         active,time);
          eventsDisplayEvent(stderr,4,event);
          }
          break;
        case EVENTS_ONTRIGGER:
          fprintf(stderr,"  selector #%d, triggered event:\n",active);
          eventsDisplayEvent(stderr,4,event);
          break;
        }
#endif
      }
    }
  if(stop==1) eventsHandle(event,selector);

  // Second pass, wait for descriptor or timeout event
  else{
    set=eventsBuildSet(&max,&nb);
    struct timeval timer=eventsNextTimer();
    struct timeval save=timer;
    struct timeval *param;
    if(nb==0 && timer.tv_sec<0) return;
    if(timer.tv_sec<0) param=NULL; else param=&timer;
#ifdef DEBUG_EVENTS
    fprintf(stderr,"  no active selector,");
    if(param==NULL)
      fprintf(stderr," waiting indefinitely,");
    else
      fprintf(stderr," waiting %d sec and %d usec,",
                     (int)param->tv_sec,(int)param->tv_usec); 
    fprintf(stderr," waiting on %d descriptor(s).\n",nb); 
#endif
    status=select(max+1,&set,NULL,NULL,param);
    if(status<0){ perror("eventsScan.select (block)"); exit(-1); }
    long int delta=1000000*(save.tv_sec-timer.tv_sec)+
                   save.tv_usec-timer.tv_usec;
    eventsUpdateTimers(delta);
    }
  }
}
