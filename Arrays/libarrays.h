/*
 * Common definitions for handling associative arrays
 */

////
// Constants
////

#define		AARRAY_NUMERIC_INDEX	1
#define		AARRAY_COMPACT_VALUE	2
#define		AARRAY_DONT_FREE	4
#define		AARRAY_END_OF_ARRAY	8

#define		AARRAY_FORCE_NUMERIC	1
#define		AARRAY_DONT_COMPACT	2
#define		AARRAY_DONT_DUPLICATE	4

////
// Structures
////

typedef struct{
  unsigned char flags;
  char *index;
  void *data;
  int size;
  } AssocArray;

////
// Prototypes
////

int arraysGetSize(AssocArray *array);
int arraysTestIndex(AssocArray *array,char *index,unsigned char flags);
void *arraysGetValue(
  AssocArray *array,char *index,int *size,unsigned char flags);
int arraysSetValue(
  AssocArray **array,char *index,void *data,int size,unsigned char flags);
void arraysFreeArray(AssocArray *array);
void arraysDisplayArray(FILE *output,AssocArray *array);
