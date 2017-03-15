//
// Created by yuech on 1/5/2017.
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PROMPT "Please enter next command."
#define WELLDONE 0
#define OOPS -1
#define CONTINUE 1

struct job{
    char *cmd;
    pid_t pid;
    int bg;
};

struct job bg_jobs[20];
char *input;
pid_t fg;
int get_cmd(char *args[], int *bg);
int run_bg(char *args[], int *bg);
void sig_handler(int sig);
int built_in(char *args[], int *bg);
int add_to_buffer(struct job a_job, struct job buffer[]);
int exec_cmd(char *args[], int *bg);
int redirect(char *args[], int *bg);

/* parse input into tokens stored in args[]
 */
int parse_input(char *args[], int *bg)
{
    char *copy_input = (char *)malloc(sizeof(input)+1);
    strcpy(copy_input, input);
    if(strlen(copy_input) !=0)
    {
        char *delimiter = " \t\n";
        args[0] = strtok(copy_input, delimiter);
        int i = 0;
        while(args[i] != NULL)
        {
            i++;
            args[i] = strtok(NULL, delimiter);
        }
    }
    else get_cmd(args, bg);
    return WELLDONE;
}

/* drop the '&', if any, in the last token.
 * drop all extra spaces after the last arguments.
 * return 1 if the command should run in the background.
 * return 0 otherwise.
 */
int run_bg(char *args[], int *bg) {
    int i = 0;
    while (args[i] != NULL) { i++; }

    if (i == 0){ *bg = 0;}
    else if (strcmp(args[i-1], "&") == 0)
    {
        args[i-1] = NULL;
        *bg = 1;
    }
    else
    {
        int len = strlen(args[i-1]);    // strlen does not count the '\0'.
        char last_token[len + 1];   // one more space for '\0'.
        strcpy(last_token, args[i-1]);    // strcpy copies the '\0'.

        if (last_token[len-1] == '&')
        {
            last_token[len-1] = '\0';
            strcpy(args[i-1], last_token);
            *bg = 1;
        }
        else *bg = 0;
    }
    return WELLDONE;
}

/* get input
 * parse input
 * check if run background.
 */
int get_cmd(char *args[], int *bg)
{
    size_t size_buffer;
    if( getline(&input, &size_buffer, stdin) !=-1)
    {
        parse_input(args, bg);
        run_bg(args, bg);
        return WELLDONE;
    }
    else return OOPS;
}

int piping(char *args[], int *bg)
{
    char *args_l[20], *args_r[20];
    int i = 0, j = 0;
    while (args[i] != NULL)
    {
        if (strcmp(args[i], "|") == 0)
        {
            args_l[i] = NULL;
            i++;
            break;
        }
        args_l[i] = args[i];
        i++;
    }
    while (args[i] != NULL)
    {
        args_r[j] = args[i];
        i++; j++;
    }
    args_r[j] = NULL;

    if (args_l[0] != NULL && args_r[0] != NULL)
    {
        int fd[2];
        pipe(fd);
        pid_t pid1 = fork(), pid2 = fork();

        if (pid1 == 0)
        {
            close(fd[0]);   // prevent other processes reading from fd[0]
            dup2(fd[1], 1);
            if(execvp(args_l[0], args_l) < 0)
            {
                perror("Piping: child execvp");
                exit(EXIT_FAILURE);
            }
        }
        if(pid1 > 0) waitpid(pid1, NULL, 0);

        if (pid2 == 0)
        {
            close(fd[1]);   // prevent other processes writing to fd[1]
            dup2(fd[0], 0);
            if(execvp(args_r[0], args_r) < 0)
            {
                perror("Piping: parent execvp");
                exit(EXIT_FAILURE);
            }
        }
        if(pid2>0)
        {
            close(fd[0]); close(fd[1]);
            waitpid(pid2, NULL, 0);
            return WELLDONE;
        }

        if( pid1 < 0 || pid2 < 0)
        {
            perror("Piping: fork");
            exit(EXIT_FAILURE);
        }
    }
}


int redirect(char *args[], int *bg){
    int i=0;
    while(args[i]!=NULL)
    {
        if(strcmp(args[i],">")==0) break;
        i++;
    }
    if(args[i+1]!=NULL && args[i+2]==NULL)
    {
        char *file = args[i+1];
        args[i] = NULL; args[i+1] = NULL;
        pid_t pid = fork();
        // child process
        if(pid==0)
        {
            int output = open(file, O_RDWR | O_CREAT);
            dup2(output,1);
            close(output);
            if(execvp(args[0], args) < 0)
            {
                perror("redirect: child execvp");
                exit(EXIT_FAILURE);
            }
        }
        if(pid<0)
        {
            perror("redirect: fork");
            exit(EXIT_FAILURE);
        }
    }
}

void sig_handler_fg(int sig){
    kill(fg, SIGKILL);
}

/* If the command is "cwd", "pwd", "exit", "fg" or "jobs", using library functions.
 * Return -1 if the command is not a built-in command or a built-in command without appropriate syntax.
 * Return 0 on success.
 */
int built_in(char *args[], int *bg)
{
    if(strcmp(args[0], "cd")==0)
    {
        chdir(args[1]);
        return WELLDONE;
    }
    else if(strcmp(args[0], "pwd")==0)
    {
        char *buffer = (char *)malloc(200*sizeof(char));
        getcwd(buffer, 200*sizeof(char));
        printf("%s\n", buffer);
        free(buffer);
        return WELLDONE;
    }
    else if(strcmp(args[0], "exit")==0) exit(EXIT_SUCCESS);
    else if(strcmp(args[0], "fg")==0)
    {
        if (args[1] != NULL)
        {
            int i = atoi(args[1])-1;
            if(bg_jobs[i].cmd != NULL && bg_jobs[i].bg == 1)
            {
                fg = bg_jobs[i].pid;
                int status;
                *bg = 0;
                bg_jobs[i].bg = 0;
                if(signal(SIGINT, sig_handler_fg) == SIG_ERR) perror("Event handling");
                do {
                    if (waitpid(fg, &status, WUNTRACED | WCONTINUED) == -1) {
                        perror("exec_cmd: parent waitpid");
                        exit(EXIT_FAILURE);
                    }
                } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            }
            else printf("Job doesn't exist in the background,\n");
            return WELLDONE;
        }
        else
        {
            perror("missing argument.\n");
            return OOPS;
        }
    }
    else if(strcmp(args[0], "jobs")==0)
    {
        if (args[1] != NULL) printf("jobs: ignoring non-option arguments.\n");
        int i = 0;
        while (i < sizeof(bg_jobs))
        {
            if (bg_jobs[i].cmd == NULL) break;
            else
            {
                printf("%d %d %s", i + 1, bg_jobs[i].pid, bg_jobs[i].cmd);
                i++;
            }
        }
        return WELLDONE;
    }
    else return OOPS;
}

int add_to_buffer(struct job a_job, struct job buffer[])
{
    int i=0;
    while(buffer[i].cmd!=NULL) i++;
    buffer[i] = a_job;
    return WELLDONE;
}

void sig_handler(int sig){
    //kill(getpid(), SIGKILL);
    exit(EXIT_SUCCESS);
}

int exec_cmd(char *args[], int *bg)
{
    pid_t pid = fork();
    int status;
    // child process
    if(pid == 0)
    {
        // ctrl+c only kills process running in the foreground
        if(!*bg)
        {
            // register signals
            if(signal(SIGINT, sig_handler) == SIG_ERR) perror("Event handling");
        }
        if(execvp(args[0], args) < 0)
        {
            perror("exec_cmd: child execvp");
            exit(EXIT_FAILURE);
        }
        return WELLDONE;
    }
    // parent process
    else if(pid > 0)
    {
        // register signals
        if (signal(SIGINT, SIG_IGN) == SIG_ERR) perror("Event handling");
        // if the command should be executed in the background, parent process returns immediately.
        if (!*bg)
        {
            do {
                if (waitpid(pid, &status, WUNTRACED | WCONTINUED) == -1) {
                    perror("exec_cmd: parent waitpid");
                    exit(EXIT_FAILURE);
                }
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }
        else
        {
            struct job a_job;
            a_job.cmd = (char *)malloc(sizeof(char)*50);
            strcpy(a_job.cmd, input);
            a_job.pid = pid;
            a_job.bg = 1;
            add_to_buffer(a_job, bg_jobs);
        }
        return WELLDONE;
    }
    else
    {
        perror("exec_cmd fork");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    char *args[20];
    input = (char *)malloc(sizeof(char)*100);
    int *bg = (int *)malloc(sizeof(int));
    while(1)
    {
        signal(SIGTSTP, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        printf("%s\n", PROMPT);
        // If read command successfully
        if ( get_cmd(args, bg) != OOPS )
        {
            if ( args[0] != NULL)
            {
                if( strchr(input, '>')!=NULL) redirect(args, bg);
                else if( strchr(input, '|')!=NULL) piping(args, bg);
                else if( built_in(args, bg)== OOPS) exec_cmd(args, bg);
            }
        }
    }
    return 0;
}


