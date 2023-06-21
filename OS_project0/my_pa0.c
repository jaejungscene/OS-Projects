/**********************************************************************
 * Copyright (c) 2021
 *  Sang-Hoon Kim <sanghoonkim@ajou.ac.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 **********************************************************************/

/*====================================================================*/
/*          ****** DO NOT MODIFY ANYTHING FROM THIS LINE ******       */
#include <stdio.h>
#include "types.h"
#include "list_head.h"

/* Declaration for the stack instance defined in pa0.c */
extern struct list_head stack;

/* Entry for the stack */
struct entry {
	struct list_head list;
	char *string;
  int x;
};
/*          ****** DO NOT MODIFY ANYTHING ABOVE THIS LINE ******      */
/*====================================================================*/

/*====================================================================*
 * The rest of this file is all yours. This implies that you can      *
 * include any header files if you want to ...                        */

#include <stdlib.h>                    /* like this */
#include <string.h>
/**
 * push_stack()
 *
 * DESCRIPTION
 *   Push @string into the @stack. The @string should be inserted into the top
 *   of the stack. You may use either the head or tail of the list for the top.
 */
struct list_head s;

void push_stack(char *string)
{
	/* TODO: Implement this function */
  struct entry* new_entry =  (struct entry*)malloc(sizeof(struct entry));
  char* new_string = (char*)malloc(sizeof(char)*strlen(string));
  strcpy(new_string, string);
  new_entry->string = new_string;
  new_entry->x = 13;
  list_add_tail(&new_entry->list, &s);
}


/**
 * pop_stack()
 *
 * DESCRIPTION
 *   Pop a value from @stack and return it through @buffer. The value should
 *   come from the top of the stack, and the corresponding entry should be
 *   removed from @stack.
 *
 * RETURN
 *   If the stack is not empty, pop the top of @stack, and return 0
 *   If the stack is empty, return -1
 */
int pop_stack(char *buffer, int* value)
{
	/* TODO: Implement this function */

  if(list_empty(&s))
	  return -1; /* Must fix to return a proper value when @stack is not empty */
  else{
    struct entry* top_entry = list_last_entry(&s, struct entry, list);
    strcpy(buffer, top_entry->string);
    *value = top_entry->x;
    list_del(&top_entry->list);
    free(top_entry->string);
    free(top_entry);
    return 0;
  }
}


/**
 * dump_stack()
 *
 * DESCRIPTION
 *   Dump the contents in @stack. Print out @string of stack entries while
 *   traversing the stack from the bottom to the top. Note that the value
 *   should be printed out to @stderr to get properly graded in pasubmit.
 */
void dump_stack(void)
{
	/* TODO: Implement this function */
  struct entry *i;
  list_for_each_entry(i, &s, list)
  {
    fprintf(stderr,"%s\n", i->string);
  }
}

int main()
{
  INIT_LIST_HEAD(&s);
  char buffer[30];
  int value;
  int command;
  while(1){
    printf("Enter command (1)push (2)pop (3)print (else)exit >> ");
    scanf("%d", &command);
    if(command == 1){
      printf("Enter string >> ");
      scanf("%s", buffer);
      push_stack(buffer);
    }
    else if(command == 2){
		  memset(buffer, 0x00, 30);
      pop_stack(buffer, &value);
      printf("poped string is \"%s and %d\"\n", buffer, value);
    }
    else if(command == 3){
      printf("\n");
      dump_stack();
    }
    else{
      break;
    }
  }
  


  // struct list_head s;
  // INIT_LIST_HEAD(&s); //********

  // if(list_empty(&s))
  //   printf("true\n\n");
  // else
  //   printf("\nfalse\n");

  // struct entry *temp1 = (struct entry *)malloc(sizeof(struct entry));
  // temp1->string = "hello";
  // list_add_tail(&(temp1->list), &s); //******

  // struct entry *temp2 = (struct entry *)malloc(sizeof(struct entry));
  // temp2->string = "jaejung";
  // list_add_tail(&(temp2->list), &s); //******

  // struct entry *i;
  // list_for_each_entry(i, &s, list)
  // {
  //   printf("%s\n", i->string);
  // }

  // if(list_empty(&s))
  //   printf("\ntrue\n");
  // else
  //   printf("\nfalse\n");

  // list_del(&temp1->list);

  // list_for_each_entry(i, &s, list)
  // {
  //   printf("\n%s\n", i->string);
  // }

  // free(temp1);
  // free(temp2);
}