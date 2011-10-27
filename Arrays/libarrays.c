/*
 * Common code for handling events
 */

////
// Include files
////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libarrays.h"

////
// Macros
////

////
// Global variables
////

////
// Private prototypes
////

static int _arraysSetValue(
  AssocArray **array,int *index,void *data,int size,unsigned char flags);
static void *_arraysGetValue(AssocArray *array,int index,int *size);
static int _arraysCopyValue(
  AssocArray *array,int index,void *data,int size,unsigned char flags);
static void _arraysFreeValue(AssocArray *array,int index);

////
// Functions
////

//
// Get array size
//
int arraysGetSize(AssocArray *array){
int i=0;
if(array==NULL) return 0;
while((array[i].flags&AARRAY_END_OF_ARRAY)==0) i++;
return i++;
}

//
// Test index presence (numeric index)
//
int arraysTestIndex(AssocArray *array,char *index,unsigned char flags){
if(array==NULL) return -1;
int nindex=-1;
if((flags&AARRAY_FORCE_NUMERIC)!=0) nindex=atoi(index);
int i=0;
while((array[i].flags&AARRAY_END_OF_ARRAY)==0){
  if((flags&AARRAY_FORCE_NUMERIC)!=0 && 
     (array[i].flags&AARRAY_NUMERIC_INDEX)!=0 &&
     (int)array[i].index==nindex) return i;
  if((flags&AARRAY_FORCE_NUMERIC)==0 && 
     (array[i].flags&AARRAY_NUMERIC_INDEX)==0 &&
     strcmp(array[i].index,index)==0) return i;
  i++;
  }
return -1;
}

//
// Extract value from array
//
static void *_arraysGetValue(AssocArray *array,int index,int *size){
if(index<0){ if(size!=NULL) *size=0; return NULL; }
if(size!=NULL) *size=array[index].size;
if((array[index].flags&AARRAY_COMPACT_VALUE)!=0)
  return (void *)&(array[index].data);
else
  return array[index].data;
}

//
// Return value associated to an index (numeric index)
//
void *arraysGetValue(
  AssocArray *array,char *index,int *size,unsigned char flags){
int i=arraysTestIndex(array,index,flags);
return _arraysGetValue(array,i,size);
}

//
// Copy value for storage into an array
//
static int _arraysCopyValue(
  AssocArray *array,int index,void *data,int size,unsigned char flags){
array[index].flags=flags;
array[index].size=size;
if((flags&AARRAY_COMPACT_VALUE)!=0){
  bzero(&(array[index].data),sizeof(void *));
  memcpy(&(array[index].data),data,size);
  }
else{
  if((flags&AARRAY_DONT_FREE)!=0)
    array[index].data=data;
  else{
    void *copy=(void *)malloc(size);
    if(copy==NULL) return -1;
    memcpy(copy,data,size);
    array[index].data=copy;
    }
  }
return 0;
}

//
// Generic function for storing a value into an array
//
static int _arraysSetValue(
  AssocArray **array,int *index,void *data,int size,unsigned char flags){
if(*index>=0){
  _arraysFreeValue(*array,*index);
  return _arraysCopyValue(*array,*index,data,size,flags); 
  }
else{
  int nb=arraysGetSize(*array);
  *array=(void *)realloc(*array,(nb+2)*sizeof(AssocArray));
  if(*array==NULL) return -1;
  (*array)[nb+1].flags=AARRAY_END_OF_ARRAY; 
  *index=nb;
  return _arraysCopyValue(*array,nb,data,size,flags); 
  }
return 0;
}
 
//
// Add value to associative array
//
int arraysSetValue(
  AssocArray **array,char *index,void *data,int size,unsigned char flags){
int i=arraysTestIndex(*array,index,flags);
int save=i;
unsigned char iflags=0;
int nindex=-1;
if((flags&AARRAY_FORCE_NUMERIC)!=0){
  nindex=atoi(index);
  iflags |= AARRAY_NUMERIC_INDEX;
  }
if((flags&AARRAY_DONT_COMPACT)==0 && size<=sizeof(void *))
  iflags |= AARRAY_COMPACT_VALUE;
if((flags&AARRAY_DONT_DUPLICATE)!=0){
  iflags &= ~AARRAY_COMPACT_VALUE;
  iflags |= AARRAY_DONT_FREE;
  }
int result=_arraysSetValue(array,&i,data,size,iflags);
if(save<0){
  if((flags&AARRAY_FORCE_NUMERIC)!=0)
    (*array)[i].index=(char *)nindex;
  else{
    (*array)[i].index=(char *)malloc(strlen(index)+1);
    strcpy((*array)[i].index,index);
    }
  }
return result;
}

//
// Free array value 
//
static void _arraysFreeValue(AssocArray *array,int index){
if((array[index].flags&AARRAY_COMPACT_VALUE)==0 &&
   (array[index].flags&AARRAY_DONT_FREE)==0)
  free(array[index].data);
}

//
// Free whole array
//
void arraysFreeArray(AssocArray *array){
if(array==NULL) return;
int i=0;
while((array[i].flags&AARRAY_END_OF_ARRAY)==0){
  if((array[i].flags&AARRAY_NUMERIC_INDEX)==0) free(array[i].index);
  _arraysFreeValue(array,i);
  i++;
  }
free(array);
}

//
// Display whole array
//
void arraysDisplayArray(FILE *output,AssocArray *array){
if(array==NULL){
  fprintf(output,"Array is void\n");
  return;
  }
int size=arraysGetSize(array);
fprintf(output,"Array of size %d:\n",size);
int i=0,j;
while((array[i].flags&AARRAY_END_OF_ARRAY)==0){
  char tindex='_',compact='_',duplicate='D';
  if((array[i].flags&AARRAY_NUMERIC_INDEX)!=0) tindex='N';
  if((array[i].flags&AARRAY_COMPACT_VALUE)!=0) compact='C';
  if((array[i].flags&AARRAY_DONT_FREE)!=0) duplicate='_';
  fprintf(output,"  [%c%c%c] ",tindex,compact,duplicate);
  if((array[i].flags&AARRAY_NUMERIC_INDEX)==0)
    fprintf(output,"%s => ",array[i].index);
  else
    fprintf(output,"%d => ",(int)array[i].index);
  int data_size;
  void *value=_arraysGetValue(array,i,&data_size);
  if(data_size>=10) fprintf(output,"\n    ");
  for(j=0;j<data_size;j++){
    fprintf(output,"%02hhx ",((char *)value)[j]);
    if(j>0 && (j%16==15)){
      fprintf(output,"\n");
      if(j<data_size-1) fprintf(output,"    ");
      }
    }
  if(data_size==0 || (j>0 && (j%16!=0))) fprintf(output,"\n");
  i++;
  }
}
