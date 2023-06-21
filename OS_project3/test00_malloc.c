#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "malloc.h"
#include "types.h"
#include "list_head.h"

#define ALIGNMENT 32
#define HDRSIZE sizeof(header_t)

static LIST_HEAD(free_list); // Don't modify this line
static algo_t g_algo;        // Don't modify this line  // placement policy
static void *bp;             // Don't modify thie line  // first address of dynamic space

/***********************************************************************
 * extend_heap()
 *
 * DESCRIPTION
 *   allocate size of bytes of memory and returns a pointer to the
 *   allocated memory.
 *
 * RETURN VALUE
 *   Return a pointer to the allocated memory.
 */
void *my_malloc(size_t size)
{
  /* Implement this function */
  void* ptr;
  
  if(list_empty(&free_list)){ // if free_list is empty
    // 맨 앞 공간에 header를 넣고 32 bytes를 건너뛴 ptr을 반환한다.
    ptr = sbrk( ALIGNMENT + ((size/ALIGNMENT) * ALIGNMENT) );
  // printf("1ptr : %p\n", ptr);

    ((header_t*)ptr)->size = size;
    ((header_t*)ptr)->free = false; //<--------------test
    list_add_tail( &(((header_t*)ptr)->list) , &free_list );
    ptr = ptr + ALIGNMENT;
    return ptr;
  }

  header_t *i;
  if(g_algo == FIRST_FIT)
  {
    list_for_each_entry(i, &free_list, list){
      if(i->free == true && i->size >= size){
        break;
      }
    }
  }
  else if(g_algo == BEST_FIT)
  {
    header_t *best = NULL;
    list_for_each_entry(i, &free_list, list){
      if(i->free == true && i->size >= size){
        if(best != NULL){
          if(best->size > i->size){
            best = i;
          }
        }
        else{
          best = i;
        }
      }
    }
  }

  if(&i->list == &free_list){
    /* free한 공간이 없거나 free한 공간 중에서 할당가능한 공간을 찾지 못함 */

    list_for_each_entry(i, &free_list, list){
      if(i->free == true && i->size >= size){
        break;
      }
    }
      ptr = sbrk( ALIGNMENT + ((size/ALIGNMENT) * ALIGNMENT) );
  // printf("2ptr : %p\n", ptr);
      ((header_t*)ptr)->size = size;
      ((header_t*)ptr)->free = false;
      list_add_tail( &(((header_t*)ptr)->list) , &free_list );
      ptr = ptr + ALIGNMENT;
      return ptr;
  }
  else{
  // printf("reach\n");
      i->size = i->size - ((size/ALIGNMENT) * ALIGNMENT) - ALIGNMENT;
      ptr = i + (size/HDRSIZE);
      // printf("%p\n", ((size/ALIGNMENT) * ALIGNMENT) );
      // printf("%p\n", (size/ALIGNMENT) + i );
      // printf("i : %p\n", i);
      // printf("func ptr : %p\n", ptr);

      *(header_t*)ptr = *i; // free 헤더 정보를 뒤로 옮김
      // printf("ptr size : %d\n", ((header_t*)ptr)->size );
      // printf("i size : %d\n", i->size );

      header_t *prev = list_prev_entry(i, list);

      list_replace( &i->list, &(((header_t*)ptr)->list) ); // 옮긴 헤더 추가
      i->free = false;
      i->size = size;

      // printf("ptr size : %d\n", ((header_t*)ptr)->size );
      // printf("i size : %d\n", i->size );

      list_add(&i->list, &prev->list); // prev -- (i넣음) -- ptr
      i = i + 1;
      return i;
  }


  return NULL;
}

/***********************************************************************
 * my_realloc()
 *
 * DESCRIPTION
 *   tries to change the size of the allocation pointed to by ptr to
 *   size, and returns ptr. If there is not enough memory block,
 *   my_realloc() creates a new_head allocation, copies as much of the old
 *   data pointed to by ptr as will fit to the new_head allocation, frees
 *   the old allocation.
 *
 * RETURN VALUE
 *   Return a pointer to the reallocated memory
 */
void *my_realloc(void *ptr, size_t size)
{
  /* Implement this function */

  void *new_ptr = my_malloc(size);
  my_free(ptr);
  // header_t *i;
  // list_for_each_entry(i, &free_list, list){
  //   if(i->free == true && i->size >= size){
  //     break;
  //   }
  // }

  // if(&i->list == &free_list){
  //   // reallocation할 공간을 찾지 못함
  //   void *new_ptr = sbrk( ALIGNMENT + ((size/ALIGNMENT) * ALIGNMENT) );
  //   ((header_t*)new_ptr)->size = size;
  //   ((header_t*)new_ptr)->free = false;
  //   list_add_tail( &(((header_t*)new_ptr)->list), &free_list );
  //   ((header_t*)(ptr-ALIGNMENT))->free = true; // 새로운 공간 할당


    
  //   my_free(ptr);
    
  // }
  // else{

  // }

  return new_ptr;
}

/***********************************************************************
 * my_realloc()
 *
 * DESCRIPTION
 *   deallocates the memory allocation pointed to by ptr.
 */
void my_free(void *ptr)
{
  /* Implement this function */

  ptr = ptr - ALIGNMENT;

  ((header_t*)ptr)->free = true;
  header_t *prev = list_prev_entry((header_t*)ptr, list);
  header_t *next = list_next_entry((header_t*)ptr, list);

// header_t *i;
// list_for_each_entry(i, &free_list, list){
//   printf("{ %p }\n", i);
// }

// printf("%p\n", ptr);
// printf("%p\n", next);
// printf("%d\n", &prev->free);
// printf("%p\n", &free_list);

//   if(next == &free_list){
// printf("dasklhf\n");
//   if(prev->free == true){
//     list_del( &(((header_t*)ptr)->list) );
//     prev->size = prev->size + ((header_t*)ptr)->size + ALIGNMENT;
//   }    
//   }
//   else{

  if(&prev->list != &free_list &&  &next->list != &free_list  &&\
      prev->free == true       &&  next->free == true)
  {

    list_del( &(((header_t*)ptr)->list) );
    list_del( &(next->list) );
    prev->size = prev->size + ((header_t*)ptr)->size + next->size \
                  + (ALIGNMENT*2);
  }
  else if(&prev->list != &free_list && prev->free == true){
    list_del( &(((header_t*)ptr)->list) );
    prev->size = prev->size + ((header_t*)ptr)->size + ALIGNMENT;
  }
  else if(&next->list != &free_list && next->free == true){
    list_del( &(next->list) );
    ((header_t*)ptr)->size = ((header_t*)ptr)->size + next->size + ALIGNMENT;
  }
  
  // }

  return;
}


/*====================================================================*/
/*          ****** DO NOT MODIFY ANYTHING BELOW THIS LINE ******      */
/*          ****** BUT YOU MAY CALL SOME IF YOU WANT TO.. ******      */
/*          ****** EXCEPT TO mem_init() AND mem_deinit(). ******      */
void mem_init(const algo_t algo)
{
  g_algo = algo;
  bp = sbrk(0);
}

void mem_deinit()
{
  header_t *header;
  size_t size = 0;
  list_for_each_entry(header, &free_list, list) {
    size += HDRSIZE + header->size;
  }
  sbrk(-size);

  if (bp != sbrk(0)) {
    fprintf(stderr, "[Error] There is memory leak\n");
  }
}

void print_memory_layout()
{
  header_t *header;
  int cnt = 0;

  printf("===========================\n");
  list_for_each_entry(header, &free_list, list) {
    cnt++;
    printf("%c %ld\n", (header->free) ? 'F' : 'M', header->size);
  }

  printf("Number of block: %d\n", cnt);
  printf("===========================\n");
  return;
}
