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
  size_t size_align;
  if((size%ALIGNMENT) == 0)
    size_align = size;
  else
    size_align = ALIGNMENT + ((size/ALIGNMENT)*ALIGNMENT);
  
  if(list_empty(&free_list)){ // 처음으로 공간을 할당할 때
    // 맨 앞 공간에 header를 넣고 32 bytes를 건너뛴 ptr을 반환한다.
    ptr = sbrk( ALIGNMENT + size_align );
    ((header_t*)ptr)->size = size_align;
    ((header_t*)ptr)->free = false;
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
    if(best != NULL) // 들어갈 수 있는 free된 공간이 있을 때
      i = best;
  }

  if(&i->list == &free_list){
    /* free된 공간이 없거나 free된 공간 중에서 할당가능한 공간을 찾지 못함 */

    int flag = 0;
    header_t *temp;
    ptr = sbrk( ALIGNMENT + size_align );

    // 뒤에 free된 공간들 중 가장 앞 공간을 찾으며, free된 공간들을 뒤로 밀어 넣는다.
    list_for_each_entry_reverse(i, &free_list, list){
      if(i->free == false && flag == 0){ // free_list가 [ ... M ]인 경우
        break;
      }
      flag = 1;
      if(i->free == false){ // free_list가 [ ... M F ]과 같이 끝에 free된 공간이 존재하는 경우
        break;
      }
      if(i->free == true){ // 새로 할당된 공간을 끝에 free된 공간들의 맨 앞에 넣기 위해 free된 공간들을 뒤로 밀어 넣는 과정
        temp = i;
        i = (void*)i + ALIGNMENT + size_align;
        list_replace( &temp->list, &i->list );
        i->free = temp->free;
        i->size = temp->size;
      }
    }

    // 끝에 free된 공간들의 맨 앞에 새로 할당된 공간을 넣음
    ptr = (void*)i + i->size + ALIGNMENT;
    ((header_t*)ptr)->size = size_align;
    ((header_t*)ptr)->free = false;
    list_add( &(((header_t*)ptr)->list) , &i->list );
    ptr = ptr + ALIGNMENT;
    return ptr;
  }
  else{
    /* 할당가능한 free된 공간이 존재함 */

    if(i->size == size_align){ // 새로 할당할 공간이 free된 공간과 정확히 일치할 때
      i->free = false;
      return i+1;
    }
    else{
      // free된 공간을 줄이고 그 공간에 새로 할당할 공간을 넣음
      ptr = i;
      i = i + (size_align/HDRSIZE); // 여기서 +1은 +32(HDSIZE)와 같다.
      i->size = ((header_t*)ptr)->size - size_align - ALIGNMENT;
      i->free = true;
      ((header_t*)ptr)->size = size_align;
      ((header_t*)ptr)->free = false;
      list_add( &i->list , &(((header_t*)ptr)->list) ); // ptr -- i
      ptr = ptr + ALIGNMENT;
      return ptr;
    }
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

  ptr = ptr - ALIGNMENT;
  if( ((header_t*)ptr)->size == size ){  // realloc하려 하는 공간이 현재 공간과 같을 때
    ptr = ptr + ALIGNMENT;
    return ptr;
  }

  ptr = ptr + ALIGNMENT;
  void *new_ptr = my_malloc(size);
  my_free(ptr);

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

  if(&prev->list != &free_list &&  &next->list != &free_list  &&\
      prev->free == true       &&  next->free == true)
  { // 양 옆에 free된 공간이 있을 경우 양 옆에 free된 공간을 현재 free할 공간과 함침
    list_del( &(((header_t*)ptr)->list) );
    list_del( &(next->list) );
    prev->size = prev->size + ((header_t*)ptr)->size + next->size \
                  + (ALIGNMENT*2);
  }
  else if(&prev->list != &free_list && prev->free == true)
  { // 앞에만 free된 공간이 있는 경우
    list_del( &(((header_t*)ptr)->list) );
    prev->size = prev->size + ((header_t*)ptr)->size + ALIGNMENT;
  }
  else if(&next->list != &free_list && next->free == true)
  { // 뒤에만 free된 공간이 있는 경우
    list_del( &(next->list) );
    ((header_t*)ptr)->size = ((header_t*)ptr)->size + next->size + ALIGNMENT;
  }

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
