#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <ucontext.h>
#include "uthread.h"
#include "list_head.h"
#include "types.h"

/* You can include other header file, if you want. */
#include <unistd.h>
#define FIX_ERR_OF_MAINTHREAD_SEGM_FAULT(tcb, head) if(tcb->tid == -1) tcb->list.prev = &head 
#define FIX_ERR_OF_MAINTHREAD_LIFETIME(tcb) if(tcb->tid == -1) tcb->lifetime = MAIN_THREAD_LIFETIME
/*******************************************************************
 * struct tcb
 *
 * DESCRIPTION
 *    tcb is a thread control block.
 *    This structure contains some information to maintain thread.
 *
 ******************************************************************/
struct tcb {
    struct list_head list;
    ucontext_t *context;
    enum uthread_state state;
    int tid;

    int lifetime; // This for preemptive scheduling
    int priority; // This for priority scheduling
};

/***************************************************************************************
 * LIST_HEAD(tcbs);
 *
 * DESCRIPTION
 *    Initialize list head of thread control block. 
 *
 **************************************************************************************/
// ready queue
LIST_HEAD(tcbs); 

// the number of tcbs
int n_tcbs = 0; 

// context to be executed when a thread is terminated
struct ucontext_t *t_context;

enum uthread_sched_policy global_policy;
/***************************************************************************************
 * next_tcb()
 *
 * DESCRIPTION
 *  
 *    Select a tcb with current scheduling policy
 *
 **************************************************************************************/
void next_tcb() {
    struct tcb *current = list_first_entry(&tcbs, struct tcb, list); // current running thread
    struct tcb *next; // next running thread

    if(global_policy == FIFO || global_policy == SJF)
    { // non_preemptive
        if(current->tid != -1 && current->state == RUNNING) // non preemptive이므로 running하고 있는 thread를 건드리지 않는다.
            return;

        if(global_policy == FIFO){
            next = fifo_scheduling(current);
        }
        else if(global_policy == SJF){
            next = sjf_scheduling(current);
        }

        if(next == current) //실행시킬 tcb가 없을 때(e.g. main thread가 실행되고 있고, 다른 thread들이 모두 join을 기다리는 상황)
            return;
    }
    else
    { // preemptive
        if(global_policy == RR){
            next = rr_scheduling(current);
        }
        else if(global_policy == PRIO){
            next = prio_scheduling(current);
        }
    }

    fprintf(stderr, "SWAP %d -> %d\n", current->tid, next->tid);
    swapcontext(current->context, next->context);
}

/***************************************************************************************
 * struct tcb *fifo_scheduling(struct tcb *next)
 *
 * DESCRIPTION
 *
 *    This function returns a tcb pointer using First-In-First-Out policy
 *
 **************************************************************************************/
struct tcb *fifo_scheduling(struct tcb *current) {
    int distance = 0; // current tcb에서 next tcb 까지의 거리
    struct tcb *next = list_next_entry(current, list);
    list_for_each_entry(next, &tcbs, list) { // 현재 running thread를 제외하고 readyQ에서 가장 앞에 위치하면서 terminated되지 않은 thread를 찾는다.
        if(next != current && next->state == READY)
            break;
        distance++;
    }

    if(&next->list != &tcbs)
    { // 다음으로 run할 tcb가 있으면, current tcb부터 next tcb 전까지의 tcb들을 readyQ의 맨 뒤로 차례대로 뺀다.
        struct tcb *temp;
        for(int i=0; i<distance; i++){
            temp = list_first_entry(&tcbs, struct tcb, list);
            FIX_ERR_OF_MAINTHREAD_SEGM_FAULT(temp, tcbs);
            list_del(&(temp->list));
            list_add_tail(&(temp->list), &tcbs);
        }
        if(current->state != TERMINATED) // non_preemptive에서는 main thread만 해당
            current->state = READY;
        next->state = RUNNING;
        return next;
    }
    else{
        return current;
    }
}

/***************************************************************************************
 * struct tcb *rr_scheduling(struct tcb *next)
 *
 * DESCRIPTION
 *
 *    This function returns a tcb pointer using round robin policy
 *
 **************************************************************************************/
struct tcb *rr_scheduling(struct tcb *current) {
    if(current->lifetime == 1){
        current->lifetime--;
        current->state = TERMINATED;
    }
    else{
        current->lifetime--;
    }

    int distance = 0; // current tcb에서 next tcb 까지의 거리
    struct tcb *next = list_next_entry(current, list);
    list_for_each_entry(next, &tcbs, list) { // 현재 running thread를 제외하고 readyQ에서 가장 앞에 위치하면서 terminated되지 않은 thread를 찾는다.
        if(next != current && next->state == READY)
            break;
        distance++;
    }

    struct tcb *temp;
    for(int i=0; i<distance; i++){ // current tcb부터 next tcb 전까지의 tcb들을 readyQ의 맨 뒤로 차례대로 뺀다.
        temp = list_first_entry(&tcbs, struct tcb, list);
        FIX_ERR_OF_MAINTHREAD_SEGM_FAULT(temp, tcbs);
        list_del(&(temp->list));
        list_add_tail(&(temp->list), &tcbs);
    }

    if(current->state != TERMINATED) // non_preemptive이므로 main thread만 해당
        current->state = READY;
    next->state = RUNNING;
    return next;
}

/***************************************************************************************
 * struct tcb *prio_scheduling(struct tcb *next)
 *
 * DESCRIPTION
 *
 *    This function returns a tcb pointer using priority policy
 *
 **************************************************************************************/
struct tcb *prio_scheduling(struct tcb *current) {
    if(current->lifetime == 1){
        current->lifetime--;
        current->state = TERMINATED;
    }
    else{
        current->lifetime--;
    }

    int max_priority = MAIN_THREAD_PRIORITY-1;
    struct tcb *walker;
    struct tcb *next = NULL;
    // 현재 running하고 있는 thread를 포함하여 terminated되지 않은 thread들 중 priority가 가장 높은 thread 선택
    list_for_each_entry(walker, &tcbs, list) { 
        if( walker->state != TERMINATED && walker->priority > max_priority ){
            max_priority = walker->priority;
            next = walker;
        }
    }

    if(next == current){ // 밑 연산을 줄이기 위해
        return next;
    }
    else{ // next tcb를 readyQ(tcbs)의 맨 앞에 넣고, current tcb를 readyQ의 맨 뒤에 넣는다.
        FIX_ERR_OF_MAINTHREAD_SEGM_FAULT(current, tcbs);
        list_del(&(current->list));
        list_del(&(next->list));
        list_add(&(next->list), &tcbs);
        list_add_tail(&(current->list), &tcbs);

        if(current->state != TERMINATED)
            current->state = READY;
        next->state = RUNNING;
        return next;
    }
}

/***************************************************************************************
 * struct tcb *sjf_scheduling(struct tcb *next)
 *
 * DESCRIPTION
 *
 *    This function returns a tcb pointer using shortest job first policy
 *
 **************************************************************************************/
struct tcb *sjf_scheduling(struct tcb *current) {
    int min_lifetime = MAIN_THREAD_LIFETIME+1;
    struct tcb *walker;
    struct tcb *next = NULL;
    list_for_each_entry(walker, &tcbs, list) { // non_preemptive이므로 lifetime이 가장 작으면서 state가 READY인 thread를 찾는다.
        FIX_ERR_OF_MAINTHREAD_LIFETIME(walker);
        if( walker != current && walker->state == READY 
        && walker->lifetime < min_lifetime ){
            min_lifetime = walker->lifetime;
            next = walker;
        }
    }

    if(next != NULL){ // next tcb를 readyQ(tcbs)의 맨 앞에 넣고, current tcb를 readyQ의 맨 뒤에 넣는다.
        FIX_ERR_OF_MAINTHREAD_SEGM_FAULT(current, tcbs);
        list_del(&(current->list));
        list_del(&(next->list));
        list_add(&(next->list), &tcbs);
        list_add_tail(&(current->list), &tcbs);

        if(current->state != TERMINATED) // non_preemptive이므로 main thread만 해당
            current->state = READY;
        next->state = RUNNING;
        return next;
    }
    else{
        return current;
    }
}

/***************************************************************************************
 * uthread_init(enum uthread_sched_policy policy)
 *
 * DESCRIPTION

 *    Initialize main tread control block, and do something other to schedule tcbs
 *
 **************************************************************************************/
void uthread_init(enum uthread_sched_policy policy) {
    global_policy = policy;

    // create main tcb
    struct tcb *main_tcb = (struct tcb*)malloc(sizeof(struct tcb));
    main_tcb->tid = MAIN_THREAD_TID;
    main_tcb->lifetime = MAIN_THREAD_LIFETIME;
    main_tcb->priority = MAIN_THREAD_PRIORITY;
    main_tcb->state = RUNNING;
    main_tcb->context = (ucontext_t*)malloc(sizeof(ucontext_t));
    getcontext(main_tcb->context);

    // create t_context that operate the "exit()" function.
    // t_context is used when a uthread is terminated.
    t_context = (ucontext_t*)malloc(sizeof(ucontext_t)); 
    getcontext(t_context);
    t_context->uc_stack.ss_sp = (char*)malloc(SIGSTKSZ);
    t_context->uc_stack.ss_size = SIGSTKSZ;
    t_context->uc_link = NULL;
    makecontext(t_context, (void*)__exit, 0);

    list_add_tail(&(main_tcb->list), &tcbs);
    n_tcbs++;
}


/***************************************************************************************
 * uthread_create(void* stub(void *), void* args)
 *
 * DESCRIPTION
 *
 *    Create user level thread. This function returns a tid.
 *
 **************************************************************************************/
int uthread_create(void* stub(void *), void* args) {
    struct tcb *new = (struct tcb*)malloc(sizeof(struct tcb));
    new->tid = ((int*)args)[0];
    new->lifetime = ((int*)args)[1];
    new->priority = ((int*)args)[2];
    new->state = READY;
    new->context = (ucontext_t*)malloc(sizeof(ucontext_t));
    getcontext(new->context);
    sigset_t mask;
    sigemptyset(&mask); // on preemtive scheduling, SIGALRM has to be NONBLOCKED
    new->context->uc_sigmask = mask;
    new->context->uc_stack.ss_sp = (char*)malloc(SIGSTKSZ); // the stack used by this context
    new->context->uc_stack.ss_size = SIGSTKSZ;
    new->context->uc_link = t_context; // next context to be executed, when the thread is terminated
    makecontext(new->context, (void*)stub, 0);

    list_add_tail(&(new->list), &tcbs);
    n_tcbs++;
    
    return new->tid;
}

/***************************************************************************************
 * uthread_join(int tid)
 *
 * DESCRIPTION
 *
 *    Wait until thread context block is terminated.
 *
 **************************************************************************************/
void uthread_join(int tid) {
    struct tcb *temp;
    struct tcb *main_tcb;
    list_for_each_entry(main_tcb, &tcbs, list){ // find the main tcb
        if (-1 == main_tcb->tid)
            break;
    }
    list_for_each_entry(temp, &tcbs, list){ // find the tcb about the tid
        if (tid == temp->tid)
            break;
    }

    if(tid == 0)    __create_run_timer(); // start scheduler()
    
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask,SIGALRM);
    getcontext(main_tcb->context); // for terminated thread going back here, and joining
    while(1){ // remove the tcb if the tcb is terminated
        if(temp->state == TERMINATED){
            sigprocmask(SIG_BLOCK, &mask, NULL);
            list_del(&(temp->list));
            fprintf(stderr, "JOIN %d\n", temp->tid);
            free(temp->context->uc_stack.ss_sp);
            free(temp->context);
            free(temp);
            temp = NULL;
            n_tcbs--;
            sigprocmask(SIG_UNBLOCK, &mask, NULL);
            break;
        }
    }
}

/***************************************************************************************
 * __exit()
 *
 * DESCRIPTION
 *
 *    When your thread is terminated, the thread have to modify its state in tcb block.
 *
 **************************************************************************************/
void __exit() {
    // non preemptive scheduling의 경우에만 uthread들이 worker()를 끝내고 도달할 수 있다.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask,SIGALRM);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    struct tcb *exit_tcb = list_first_entry(&tcbs, struct tcb, list);
    exit_tcb->state = TERMINATED;
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    usleep(1000); // terminated된 uthread는 scheduler가 떠 scheduling되기를 기다린다.
}

/***************************************************************************************
 * __initialize_exit_context()
 *
 * DESCRIPTION
 *
 *    This function initializes exit context that your thread context will be linked.
 *
 **************************************************************************************/
void __initialize_exit_context() {

    /* TODO: You have to implement this function. */
}

/***************************************************************************************
 *   
 * DO NOT MODIFY UNDER THIS LINE!!!
 *
 **************************************************************************************/

static struct itimerval time_quantum;
static struct sigaction ticker;

void __scheduler() {
    if(n_tcbs > 1)
        next_tcb();
}

void __create_run_timer() {

    time_quantum.it_interval.tv_sec = 0;
    time_quantum.it_interval.tv_usec = SCHEDULER_FREQ;
    time_quantum.it_value = time_quantum.it_interval;
    
    ticker.sa_handler = __scheduler;
    sigemptyset(&ticker.sa_mask);
    sigaction(SIGALRM, &ticker, NULL);
    ticker.sa_flags = 0;
    
    setitimer(ITIMER_REAL, &time_quantum, (struct itimerval*) NULL);
}

void __free_all_tcbs() {
    struct tcb *temp;

    list_for_each_entry(temp, &tcbs, list) {
        if (temp != NULL && temp->tid != -1) {
            list_del(&temp->list);
            free(temp->context);
            free(temp);
            n_tcbs--;
            temp = list_first_entry(&tcbs, struct tcb, list);
        }
    }

    temp = NULL;
    free(t_context);
}