/* Test file for events */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libevents.h"

////
// Constants
////

#define MAX_BUFFER      1024
#define PROMPT_ANSWER   "> "
#define DISPLAY_STRING  "string example"
#define DISPLAY_STRING1 "substring example one"
#define DISPLAY_STRING2 "substring example two"
#define DISPLAY_STRING3 "substring example three"
#define DISPLAY_STRING4 "substring example four"
#define CMD_STOP        "stop"

////
// Functions
////

//
// Display standard input
//

unsigned char actionStandardInput(EventsEvent *event,EventsSelector *selector){
char buffer[MAX_BUFFER];
int descriptor=selector->selector.descriptor;
int size=read(descriptor,buffer,MAX_BUFFER);
if(size>0){
  write(1,PROMPT_ANSWER,strlen(PROMPT_ANSWER));
  write(1,buffer,size);
  }
if(strncmp(buffer,CMD_STOP,strlen(CMD_STOP))==0) return -1; else return 0;
}

//
// Display string
//

unsigned char actionDisplay(EventsEvent *event,EventsSelector *selector){
char *string=(char *)event->data_init;
char *substring=(char *)selector->data_this;
fprintf(stdout,"String: %s\n",string);
fprintf(stdout,"SubString: %s\n",substring);
return 0;
}

////
// Main procedure
////

int main(void){
int event_descriptor=eventsCreate(0,NULL);
int event_display=eventsCreate(1,(void *)DISPLAY_STRING);
eventsAddAction(event_descriptor,actionStandardInput,0);
eventsAddAction(event_display,actionDisplay,0);
eventsAssociateDescriptor(event_descriptor,0,NULL);
eventsTrigger(event_display,(void *)DISPLAY_STRING1);
eventsTrigger(event_display,(void *)DISPLAY_STRING2);
eventsTrigger(event_display,(void *)DISPLAY_STRING3);
eventsTrigger(event_display,(void *)DISPLAY_STRING1);
eventsTrigger(event_display,(void *)DISPLAY_STRING2);
eventsTrigger(event_display,(void *)DISPLAY_STRING3);
eventsSchedule(event_display,5000000,(void *)DISPLAY_STRING4);
eventsScan();
exit(0);
}

