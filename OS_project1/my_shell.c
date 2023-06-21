#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#include <ctype.h>

#include <string.h>
#include "types.h"
#include "list_head.h"
#include "parser.h"
#include "parser.c"

static int __process_command(char * command);

struct entry {
	struct list_head list;
	char *command;
};

/***********************************************************************
 * struct list_head history
 *
 * DESCRIPTION
 *   Use this list_head to store unlimited command history.
 */
LIST_HEAD(history);


/***********************************************************************
 * run_command()
 *
 * DESCRIPTION
 *   Implement the specified shell features here using the parsed
 *   command tokens.
 *
 * RETURN VALUE
 *   Return 1 on successful command execution
 *   Return 0 when user inputs "exit"
 *   Return <0 on error
 */
static int run_command(int nr_tokens, char *tokens[])
{
	if (strcmp(tokens[0], "exit") == 0) return 0;
  int status = 0;


  /**** check if there is the pipe("|") ****/
	int start_index = 1;
	while(tokens[start_index] != NULL){
		if(strcmp(tokens[start_index], "|") == 0){
      status = 1;
      tokens[start_index] = NULL;
      start_index++;
      break;
		}
    start_index++;
  }


  /**** command pipe("|") ****/
  if(status == 1)
  {
    if(fork() == 0){
      int p[2];
      pipe(p);
      if(fork() == 0)
      { // first command
        dup2(p[1], 1);  // 1 = stdout
        execvp(tokens[0], tokens);
        close(p[1]);
        exit(2); // 512, command not found
      }
      else
      { // second command
        wait(&status);
        if(status == 512){
          exit(3);
        }
        close(p[1]);
        dup2(p[0], 0);  // 0 = stdin
        execvp(tokens[start_index], &tokens[start_index]);
        exit(2); // 512, command not found
      }
    }
    else{
      wait(&status);
      if(status==0 || status==256)
		  {/* status==256 is status that command is executed 
			  *	but arguments is not correct */
    	  return 1;
		  }
      if(status == 512){  // second command is failed
        tokens[0] = tokens[start_index];
      }
    }
  }
  else
  {
    /**** built-in command cd ****/
    if (strcmp(tokens[0], "cd") == 0)
    {
      if (nr_tokens >= 3)
      {
        printf("-shell: cd: too many arguments\n");
      }
      else if (tokens[1] == NULL ||
               strcmp(tokens[1], "~") == 0)
      {
        char *home;
        home = getenv("HOME");
        chdir(home);
      }
      else
      {
        status = chdir(tokens[1]);
        if (status == -1)
          printf("-shell: cd: %s: No such file or directory\n", tokens[1]);
      }
      return 1;
    }

    /**** built-in command history ****/
    if (strcmp(tokens[0], "history") == 0)
    {
      struct entry *i;
      int index = 0;
      list_for_each_entry(i, &history, list)
      {
        fprintf(stderr, "%2d: %s", index, i->command);
        index++;
      }
      return 1;
    }

    /**** built-in command "!" ****/
    if (strcmp(tokens[0], "!") == 0)
    {
      struct entry *i;
      int num = atoi(tokens[1]);
      int index = 0;
      list_for_each_entry(i, &history, list)
      {
        if (index == num)
          break;
        index++;
      }
      char tmp[MAX_COMMAND_LEN];
      strcpy(tmp, i->command);
      __process_command(tmp);
      return 1;
    }

    /**** executing the executables ****/
    if (fork() == 0)
    { /* if command not exit, just go with the flow */
      execvp(tokens[0], tokens);
      exit(2); /* 512 */
    }
    else
    {
      wait(&status);
      if (status == 0 || status == 256)
      { /* status==256 is status that command is executed
         *	but arguments is not correct */
        return 1;
      }
    }
  }

  fprintf(stderr, "Unable to execute %s\n", tokens[0]);
	return -EINVAL;
}


/***********************************************************************
 * append_history()
 *
 * DESCRIPTION
 *   Append @command into the history. The appended command can be later
 *   recalled with "!" built-in command
 */
static void append_history(char * const command)
{
  struct entry* new_entry =  (struct entry*)malloc(sizeof(struct entry));
  char* new_command = (char*)malloc(strlen(command)+1);
  strcpy(new_command, command);
  new_entry->command = new_command;
  list_add_tail(&new_entry->list, &history);
}


/***********************************************************************
 * initialize()
 *
 * DESCRIPTION
 *   Call-back function for your own initialization code. It is OK to
 *   leave blank if you don't need any initialization.
 *
 * RETURN VALUE
 *   Return 0 on successful initialization.
 *   Return other value on error, which leads the program to exit.
 */
static int initialize(int argc, char * const argv[])
{
	return 0;
}


/***********************************************************************
 * finalize()
 *
 * DESCRIPTION
 *   Callback function for finalizing your code. Like @initialize(),
 *   you may leave this function blank.
 */
static void finalize(int argc, char * const argv[])
{

}


static int __process_command(char * command)
{
	char *tokens[MAX_NR_TOKENS] = { NULL };
	int nr_tokens = 0;

	if (parse_command(command, &nr_tokens, tokens) == 0)
		return 1;

	return run_command(nr_tokens, tokens);
}

static bool __verbose = true;
static const char *__color_start = "[0;31;40m";
static const char *__color_end = "[0m";

static void __print_prompt(void)
{
	char *prompt = "$";
	if (!__verbose) return;

	fprintf(stderr, "%s%s%s ", __color_start, prompt, __color_end);
}

int main(int argc, char *const argv[])
{
	char command[MAX_COMMAND_LEN] = { '\0' };
	int ret = 0;
	int opt;

  // char c = '\n';
  // char c1 = '\0';
  // char c2 = ' ';
  // printf("%d\n", isspace(c));
  // printf("%d\n", isspace(c1));
  // printf("%d\n", isspace(c2));

  while(true){
    __print_prompt();

    if(!fgets(command, sizeof(command), stdin)) break;

		append_history(command);
    ret = __process_command(command);

    if (!ret) break;  // if command is exit
  }

	// if ((ret = initialize(argc, argv))) return EXIT_FAILURE;

  // char *x;
  // x = fgets(command, sizeof(command), stdin);
  // printf("1 %s\n", command);
  // if(!x)  printf("true\n");
  // printf("2 %s\n", x);
}