#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>

const char *sysname = "shellish";

enum return_codes {
  SUCCESS = 0,
  EXIT = 1,
  UNKNOWN = 2,
};

struct command_t {
  char *name;
  bool background;
  bool auto_complete;
  int arg_count;
  char **args;
  char *redirects[3];     // in/out redirection
  struct command_t *next; // for piping
};

/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
  int i = 0;
  printf("Command: <%s>\n", command->name);
  printf("\tIs Background: %s\n", command->background ? "yes" : "no");
  printf("\tNeeds Auto-complete: %s\n", command->auto_complete ? "yes" : "no");
  printf("\tRedirects:\n");
  for (i = 0; i < 3; i++)
    printf("\t\t%d: %s\n", i,
           command->redirects[i] ? command->redirects[i] : "N/A");
  printf("\tArguments (%d):\n", command->arg_count);
  for (i = 0; i < command->arg_count; ++i)
    printf("\t\tArg %d: %s\n", i, command->args[i]);
  if (command->next) {
    printf("\tPiped to:\n");
    print_command(command->next);
  }
}

/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
  if (command->arg_count) {
    for (int i = 0; i < command->arg_count; ++i)
      free(command->args[i]);
    free(command->args);
  }
  for (int i = 0; i < 3; ++i)
    if (command->redirects[i])
      free(command->redirects[i]);
  if (command->next) {
    free_command(command->next);
    command->next = NULL;
  }
  free(command->name);
  free(command);
  return 0;
}

/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
  char cwd[1024], hostname[1024];
  gethostname(hostname, sizeof(hostname));
  getcwd(cwd, sizeof(cwd));
  printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
  return 0;
}

/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
  const char *splitters = " \t"; // split at whitespace
  int index, len;
  len = strlen(buf);
  while (len > 0 && strchr(splitters, buf[0]) != NULL) // trim left whitespace
  {
    buf++;
    len--;
  }
  while (len > 0 && strchr(splitters, buf[len - 1]) != NULL)
    buf[--len] = 0; // trim right whitespace

  if (len > 0 && buf[len - 1] == '?') // auto-complete
    command->auto_complete = true;
  if (len > 0 && buf[len - 1] == '&') // background
    command->background = true;

  char *pch = strtok(buf, splitters);
  if (pch == NULL) {
    command->name = (char *)malloc(1);
    command->name[0] = 0;
  } else {
    command->name = (char *)malloc(strlen(pch) + 1);
    strcpy(command->name, pch);
  }

  command->args = (char **)malloc(sizeof(char *));

  int redirect_index;
  int arg_index = 0;
  char temp_buf[1024], *arg;
  while (1) {
    // tokenize input on splitters
    pch = strtok(NULL, splitters);
    if (!pch)
      break;
    arg = temp_buf;
    strcpy(arg, pch);
    len = strlen(arg);

    if (len == 0)
      continue; // empty arg, go for next
    while (len > 0 && strchr(splitters, arg[0]) != NULL) // trim left whitespace
    {
      arg++;
      len--;
    }
    while (len > 0 && strchr(splitters, arg[len - 1]) != NULL)
      arg[--len] = 0; // trim right whitespace
    if (len == 0)
      continue; // empty arg, go for next

    // piping to another command
    if (strcmp(arg, "|") == 0) {
      struct command_t *c =
          (struct command_t *)malloc(sizeof(struct command_t));
      int l = strlen(pch);
      pch[l] = splitters[0]; // restore strtok termination
      index = 1;
      while (pch[index] == ' ' || pch[index] == '\t')
        index++; // skip whitespaces

      parse_command(pch + index, c);
      pch[l] = 0; // put back strtok termination
      command->next = c;
      continue;
    }

    // background process
    if (strcmp(arg, "&") == 0)
      continue; // handled before

    // handle input redirection
    redirect_index = -1;
    if (arg[0] == '<')
      redirect_index = 0;
    if (arg[0] == '>') {
      if (len > 1 && arg[1] == '>') {
        redirect_index = 2;
        arg++;
        len--;
      } else
        redirect_index = 1;
    }
    if (redirect_index != -1) {
      command->redirects[redirect_index] = (char *)malloc(len);
      strcpy(command->redirects[redirect_index], arg + 1);
      continue;
    }

    // normal arguments
    if (len > 2 &&
        ((arg[0] == '"' && arg[len - 1] == '"') ||
         (arg[0] == '\'' && arg[len - 1] == '\''))) // quote wrapped arg
    {
      arg[--len] = 0;
      arg++;
    }
    command->args =
        (char **)realloc(command->args, sizeof(char *) * (arg_index + 1));
    command->args[arg_index] = (char *)malloc(len + 1);
    strcpy(command->args[arg_index++], arg);
  }
  command->arg_count = arg_index;

  // increase args size by 2
  command->args = (char **)realloc(command->args,
                                   sizeof(char *) * (command->arg_count += 2));

  // shift everything forward by 1
  for (int i = command->arg_count - 2; i > 0; --i)
    command->args[i] = command->args[i - 1];

  // set args[0] as a copy of name
  command->args[0] = strdup(command->name);
  // set args[arg_count-1] (last) to NULL
  command->args[command->arg_count - 1] = NULL;

  return 0;
}

void prompt_backspace() {
  putchar(8);   // go back 1
  putchar(' '); // write empty over
  putchar(8);   // go back 1 again
}

/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
  int index = 0;
  char c;
  char buf[4096];
  static char oldbuf[4096];

  // tcgetattr gets the parameters of the current terminal
  // STDIN_FILENO will tell tcgetattr that it should write the settings
  // of stdin to oldt
  static struct termios backup_termios, new_termios;
  tcgetattr(STDIN_FILENO, &backup_termios);
  new_termios = backup_termios;
  // ICANON normally takes care that one line at a time will be processed
  // that means it will return if it sees a "\n" or an EOF or an EOL
  new_termios.c_lflag &=
      ~(ICANON |
        ECHO); // Also disable automatic echo. We manually echo each char.
  // Those new settings will be set to STDIN
  // TCSANOW tells tcsetattr to change attributes immediately.
  tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

  show_prompt();
  buf[0] = 0;
  while (1) {
    c = getchar();
    // printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

    if (c == 9) // handle tab
    {
      buf[index++] = '?'; // autocomplete
      break;
    }

    if (c == 127) // handle backspace
    {
      if (index > 0) {
        prompt_backspace();
        index--;
      }
      continue;
    }

    if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
      continue;
    }

    if (c == 65) // up arrow
    {
      while (index > 0) {
        prompt_backspace();
        index--;
      }

      char tmpbuf[4096];
      printf("%s", oldbuf);
      strcpy(tmpbuf, buf);
      strcpy(buf, oldbuf);
      strcpy(oldbuf, tmpbuf);
      index += strlen(buf);
      continue;
    }

    putchar(c); // echo the character
    buf[index++] = c;
    if (index >= sizeof(buf) - 1)
      break;
    if (c == '\n') // enter key
      break;
    if (c == 4) // Ctrl+D
      return EXIT;
  }
  if (index > 0 && buf[index - 1] == '\n') // trim newline from the end
    index--;
  buf[index++] = '\0'; // null terminate string

  strcpy(oldbuf, buf);

  parse_command(buf, command);

  // print_command(command); // DEBUG: uncomment for debugging

  // restore the old settings
  tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
  return SUCCESS;
}

// Part3-b Chatroom

void run_chatroom(char *roomname, char *username) {
  char room_path[256], my_pipe[256], buffer[1024], formatted_msg[1200];

  // Create room folder and user pipe 
  strcpy(room_path, "/tmp/chatroom-");
  strcat(room_path, roomname);
  mkdir(room_path, 0777); 

  strcpy(my_pipe, room_path);
  strcat(my_pipe, "/");
  strcat(my_pipe, username);
  mkfifo(my_pipe, 0666);

  printf("Welcome to %s!\n", roomname);

  // RECEIVER: Continuous reading 
  if (fork() == 0) {
    while (1) {
      int fd = open(my_pipe, O_RDONLY);
      if (fd != -1) {
        int n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
          // Write the received message and refresh prompt using low-level write 
          write(STDOUT_FILENO, "\r", 1);
          write(STDOUT_FILENO, buffer, strlen(buffer));
          write(STDOUT_FILENO, "\n", 1);
                    
          char prompt[512];
          strcpy(prompt, "[");
          strcat(prompt, roomname);
          strcat(prompt, "] ");
          strcat(prompt, username);
          strcat(prompt, " > ");
          write(STDOUT_FILENO, prompt, strlen(prompt));
        }
        close(fd);
      }
    }
  }

  // SENDER: Iterate directory using 'exec' 
  while (1) {
    printf("[%s] %s > ", roomname, username);
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
      buffer[strcspn(buffer, "\n")] = 0;

    if (strlen(buffer) == 0) continue;

      strcpy(formatted_msg, "[");
      strcat(formatted_msg, roomname);
      strcat(formatted_msg, "] ");
      strcat(formatted_msg, username);
      strcat(formatted_msg, ": ");
      strcat(formatted_msg, buffer);

      // Directory Traversal using exec(ls) and a pipe 
      int p[2];
      pipe(p);

      if (fork() == 0) {
        dup2(p[1], STDOUT_FILENO);
        close(p[0]); 
        close(p[1]);
        execlp("ls", "ls", room_path, NULL);
        exit(1);
      }

      // Parent
      close(p[1]);
      char ls_buffer[4096];
      int bytes_read = read(p[0], ls_buffer, sizeof(ls_buffer) - 1);
        
      if (bytes_read > 0) {
        ls_buffer[bytes_read] = '\0';
        char *target_user = strtok(ls_buffer, "\n");
            
        while (target_user != NULL) {
          // Separate child for each user 
          if (fork() == 0) {
            char target_path[512];
            strcpy(target_path, room_path);
            strcat(target_path, "/");
            strcat(target_path, target_user);

            int fd_w = open(target_path, O_WRONLY | O_NONBLOCK);
            if (fd_w != -1) {
              write(fd_w, formatted_msg, strlen(formatted_msg) + 1);
              close(fd_w);
            }
            exit(0);
          }
          target_user = strtok(NULL, "\n");
        }
    }
    close(p[0]);
    wait(NULL); 
  }
}

// Helper
void print_board(char board[10][10], char *title) {
  char header[128];
  sprintf(header, "\n--- %s ---\n    A B C D E F G H I J\n", title);
  write(STDOUT_FILENO, header, strlen(header));
  write(STDOUT_FILENO, "   --------------------\n", 24);

  for (int i = 0; i < 10; i++) {
    char row_num[10];
    sprintf(row_num, "%2d |", i + 1);
    write(STDOUT_FILENO, row_num, strlen(row_num));
    for (int j = 0; j < 10; j++) {
      write(STDOUT_FILENO, &board[i][j], 1);
      write(STDOUT_FILENO, " ", 1);
    }
    write(STDOUT_FILENO, "\n", 1);
  }
  write(STDOUT_FILENO, "\n", 1);
}

// Helper for battleship
void send_to_other(char *room_path, char *my_name, char *msg) {
  int p[2];
  // Create anonymous pipe 
  if (pipe(p) == -1) return;

  // Child process: execute "ls" to list all users
  if (fork() == 0) {
    dup2(p[1], STDOUT_FILENO);
    close(p[0]);
    close(p[1]);
    execlp("ls", "ls", room_path, NULL);
    exit(1);
  }
  // Parent process reads the output of "ls"
  close(p[1]);
  char ls_buf[1024];
  int n = read(p[0], ls_buf, sizeof(ls_buf) - 1);
  close(p[0]);

  if (n > 0) {
    ls_buf[n] = '\0';
    char *user = strtok(ls_buf, "\n");
    while (user != NULL) {
    // We dont send ourselves a message
      if (strcmp(user, my_name) != 0) {
        if (fork() == 0) {
          char target_path[512];
          sprintf(target_path, "%s/%s", room_path, user);
          int fd = open(target_path, O_WRONLY | O_NONBLOCK);
          if (fd != -1) {
            write(fd, msg, strlen(msg) + 1);
            close(fd);
          }
          exit(0);
        }
      }
      user = strtok(NULL, "\n");
    }
  }
  // Wait for children
  while (waitpid(-1, NULL, WNOHANG) > 0);
}

//Helper ship placer for Battle Ship
void place_ship(char board[10][10], char *coord_str) {
  char c1_c, c2_c; // Starting and ending column letters (A–J)
  int r1, r2; // Starting and ending row numbers (1–10)
  if (sscanf(coord_str, " %c%d:%c%d", &c1_c, &r1, &c2_c, &r2) == 4) {
    int start_row = r1 - 1;
    int end_row = r2 - 1;
    int start_col = toupper(c1_c) - 'A';
    int end_col = toupper(c2_c) - 'A';

    // Mark S which means ship
    for (int i = start_row; i <= end_row; i++) {
      for (int j = start_col; j <= end_col; j++) {
        if (i >= 0 && i < 10 && j >= 0 && j < 10) {
          board[i][j] = 'S';
        }
      }
    }
      print_board(board, "SHIP PLACED");
  }
}
//Helper for Battle Ship
int all_ships_destroyed(char board[10][10]) {
  for (int i = 0; i < 10; i++) {
    for (int j = 0; j < 10; j++) {
      if (board[i][j] == 'S') {
        return 0; // still there is a ship
      }
    }
  }
  return 1; // All ships drowned
}

// PART 3-c Custom Command : Amiral Battı (Sea Battle)
void run_battleship(char *roomname, char *username) {

  char room_path[512], my_pipe[1024], buffer[2048];
  static char my_board[10][10];
  static char enemy_view[10][10];
  int receiver_started = 0;

  // Initialize boards
  for (int i = 0; i < 10; i++) {
    for (int j = 0; j < 10; j++) {
      my_board[i][j] = '.';
      enemy_view[i][j] = '.';
    }
  }

  // Setup room + fifo
  strcpy(room_path, "/tmp/chatroom-");
  strncat(room_path, roomname, sizeof(room_path) - strlen(room_path) - 1);
  mkdir(room_path, 0777);
  sprintf(my_pipe, "%s/%s", room_path, username);
  mkfifo(my_pipe, 0666);

  const char *intro =
        "\n--- BATTLESHIP: CURLYBOI EDITION ---\n"
        "Instructions:\n"
        "  1) place your ships  (example: place C3:C5)\n"
        "  2) ready\n"
        "  3) attack            (example: attack A1)\n"
        "  4) enjoy!\n\n";
  write(STDOUT_FILENO, intro, strlen(intro));

  while (1) {
    write(STDOUT_FILENO, "BattleCommand> ", 15);
    if (fgets(buffer, sizeof(buffer), stdin) == NULL)break;
    buffer[strcspn(buffer, "\n")] = 0;
    // --- READY ---
    // Player indicates readiness
    if (strcmp(buffer, "ready") == 0) {
      if (receiver_started) {
        write(STDOUT_FILENO,"You are already ready!\n", strlen("You are already ready!\n"));
        continue;
      }
      send_to_other(room_path, username, "READY_MSG");
      write(STDOUT_FILENO,"Board confirmed. Waiting for opponent...\n", strlen("Board confirmed. Waiting for opponent...\n"));
      print_board(my_board, "MY FINAL BOARD");

      // Start receiver process
      if (fork() == 0) {
        while (1) {
          int fd = open(my_pipe, O_RDONLY);
          if (fd == -1) continue;

          char rx_buf[2048];
          int n = read(fd, rx_buf, sizeof(rx_buf) - 1);
          close(fd);

          if (n <= 0) continue;
          rx_buf[n] = '\0';

          // --- ATTACK RECEIVED--- 
          if (strncmp(rx_buf, "ATTACK:", 7) == 0) {
            char col_c = rx_buf[7];
            int row = atoi(rx_buf + 8);
            int r = row - 1;
            int c = toupper(col_c) - 'A';
            char result_msg[64];

            if (my_board[r][c] == 'S') {
              my_board[r][c] = 'X'; //Marks as hitted

              sprintf(result_msg,"RESULT:HIT:%c%d",col_c,row);
              send_to_other(room_path,username,result_msg); // Sends result to enemy

              write(STDOUT_FILENO,"\n[!!!] WE GOT HIT! (",strlen("\n[!!!] WE GOT HIT! ("));
              write(STDOUT_FILENO,rx_buf + 7,strlen(rx_buf + 7));
              write(STDOUT_FILENO,")\n",2);

              if (all_ships_destroyed(my_board)) {

              sprintf(result_msg,"RESULT:WIN:%c%d",col_c,row);
              send_to_other(room_path,username,result_msg);
              write(STDOUT_FILENO,"\n*** GAME OVER - YOU LOST ***\n",31);
              exit(0);
              }
            }
            else {
              if (my_board[r][c] == '.') my_board[r][c] = 'O';

              sprintf(result_msg,"RESULT:MISS:%c%d",col_c,row);
              send_to_other(room_path,username,result_msg);
              write(STDOUT_FILENO,"\n[MISS] Opponent missed.\n",strlen("\n[MISS] Opponent missed.\n"));
            }

            print_board(my_board, "MY BOARD STATUS");
            write(STDOUT_FILENO, "BattleCommand> ", 15);
          }

          // ---RESULT RECEIVED ---
          else if (strncmp(rx_buf, "RESULT:", 7) == 0) {

            char *ptr = rx_buf + 7;// HIT:A5
            char *colon = strchr(ptr, ':');
            if (!colon) return;

            *colon = '\0';
            char *type = ptr;// HIT / MISS / WIN
            char *coord = colon + 1;// A5
            char col_c = coord[0];
            int row = coord[1] - '0';
            int r = row - 1;
            int c = toupper(col_c) - 'A';
      
            if (strcmp(type, "HIT") == 0) {
              enemy_view[r][c] = 'X';
              write(STDOUT_FILENO, "\n[HIT] Direct hit!\n", strlen("\n[HIT] Direct hit!\n"));
            } 
            else if (strcmp(type, "WIN") == 0) {
              enemy_view[r][c] = 'X';
              write(STDOUT_FILENO, "\n*** YOU WON! ***\n", strlen("\n*** YOU WON! ***\n"));
              print_board(enemy_view, "ENEMY BOARD");
              exit(0);
            } 
            else {  // MISS
              enemy_view[r][c] = 'O';
              write(STDOUT_FILENO, "\n[MISS] Shot missed.\n", strlen("\n[MISS] Shot missed.\n"));
            }
            print_board(enemy_view, "ENEMY BOARD");
            write(STDOUT_FILENO, "BattleCommand> ", 15);
          }

          // --- READY RECEIVED ---
          else if (strcmp(rx_buf, "READY_MSG") == 0) {
            write(STDOUT_FILENO,"\n[!] Enemy is ready: Let the battle begin!!!\n",strlen("\n[!] Enemy is ready: Let the battle begin!!!\n"));
            write(STDOUT_FILENO,"BattleCommand> ",15);
          }
        }
        exit(0);
      }
      receiver_started = 1; // Means game started
    }
    // --- PLACE ---
    else if (strncmp(buffer, "place ", 6) == 0) {
      if (receiver_started) { // Cannot place after game started
        write(STDOUT_FILENO,"Game already started. You cannot place ships anymore.\n",strlen("Game already started. You cannot place ships anymore.\n"));
      }
      else {
      place_ship(my_board, buffer + 6);
      }
    }
    // ---ATTACK ---
    else if (strncmp(buffer, "attack ", 7) == 0) { // Checks if ready was written
      if (!receiver_started) {
        write(STDOUT_FILENO,"Type 'ready' first!!!\n",strlen("Type 'ready' first!!!\n"));
      }
      else {
        char attack_msg[64];
        sprintf(attack_msg,"ATTACK:%s",buffer + 7);
        send_to_other(room_path,username,attack_msg); //Message send to enemy fifo
      }
    }
    // Show
    else if (strcmp(buffer, "show") == 0) {
      print_board(my_board, "MY BOARD");
    }
    // Exit
    else if (strcmp(buffer, "exit") == 0) {
      break;
    }
  }
}
void exec_with_path(struct command_t *command);// Helper function for exec written under process command

int process_command(struct command_t *command) {

  //Built-in Commands

  int r;
  if (strcmp(command->name, "") == 0)
    return SUCCESS;

  if (strcmp(command->name, "exit") == 0)
    return EXIT;

  if (strcmp(command->name, "cd") == 0) {
    if (command->arg_count > 0) {
      r = chdir(command->args[1]);
      if (r == -1)
        printf("-%s: %s: %s\n", sysname, command->name, strerror(errno));
      return SUCCESS;
    }
  }
  if (strcmp(command->name, "cut") == 0) {
    
    char delimiter = '\t'; // Deault delimeter is tab
    char *fields_string = NULL;
    int delimiter_seen = 0; 
    int field_seen = 0;

    for (int i = 1; command->args[i] != NULL; i++){
    
      if (strcmp(command->args[i], "-d") == 0 && delimiter_seen == 0){
        if (command->args[i + 1] == NULL) {
          printf("Missing delimiter\n");
          return SUCCESS;
    }
        delimiter= command->args[i+1][0];
        delimiter_seen++;
        i++;
      }

      else if (strncmp(command->args[i], "-f", 2) == 0 && field_seen == 0) {
    
        fields_string = &command->args[i][2]; 

        if (fields_string[0] == '\0') { // If nothing written after -f
          printf("Missing field after -f\n");
          return SUCCESS;
      }
        field_seen = 1;
      }
    }
    if (field_seen == 0){ // Field has to be provided
      printf("Missing field\n");
      return SUCCESS;
    }

    //Turn Fields into int array
    int fields[100];
    int field_count = 0;
    char temp[256];
    strcpy(temp, fields_string);  //strtok change original string

    char *token = strtok(temp, ",");
    while (token != NULL) {
        fields[field_count] = atoi(token);
        field_count++;
        token = strtok(NULL, ",");
    }

    // Read each line
    char line[1024];
    char delimeter_string[2] = { delimiter, '\0' };

    while (fgets(line, sizeof(line), stdin) != NULL) {

      char *running = line;// to protect first line
      char *token;
      int token_count = 0;
      int printed = 0;

      while ((token = strsep(&running, delimeter_string)) != NULL) {
        token_count++;

        for (int i = 0; i < field_count; i++){
          if(token_count== fields[i]){
            if (printed) {
              printf("%c", delimiter);
            }
            printf("%s", token);
            printed = 1;
          }
        }
      }
      printf("\n");
    }
    return SUCCESS;
  }

  // Part3-b chatroom
  if (strcmp(command->name, "chatroom") == 0) {
    if (command->arg_count < 3) { // Expecting: chatroom <roomname> <username>
      printf("Usage: chatroom <roomname> <username>\n");
      return SUCCESS;
    }
    // command->args[1] is <roomname>, command->args[2] is <username>
    run_chatroom(command->args[1], command->args[2]);
    return SUCCESS;
  }
  //Part3-c amiral battı
  if (strcmp(command->name, "battleship") == 0) {
    if (command->arg_count < 2) {
      write(STDOUT_FILENO, "Usage: battleship <roomname> <username>\n", 40);
    } 
    else {
    // command->args[1] is <roomname>, command->args[2] is <username>
    run_battleship(command->args[1], command->args[2]);
    }
    return SUCCESS;
  }

  // PIPE HANDLING 
  if (command->next) {

    int fd[2];
    pipe(fd); // fd[0] = read end, fd[1] = write end

    pid_t pid1 = fork();

    if (pid1 == 0) { // first child 
      dup2(fd[1], STDOUT_FILENO); // Redirect stdout to pipe write end
      close(fd[0]);
      close(fd[1]);

      exec_with_path(command);   
      exit(1);
    }
    pid_t pid2 = fork();

    if (pid2 == 0) { // second child 
      dup2(fd[0], STDIN_FILENO); // Redirect stdin to pipe read end
      close(fd[1]);
      close(fd[0]);

      process_command(command->next); // Recursively call next
      exit(0);
    }
    // Close pipe
    close(fd[0]);
    close(fd[1]);
    // Wait for children to finish
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);

    return SUCCESS;
  }
  

  pid_t pid = fork();
  if (pid == 0) // child
  {

    // (<) Redirection
    // Replace stdin with file
    if (command->redirects[0]){
      int fd = open(command->redirects[0], O_RDONLY); 
      dup2(fd, STDIN_FILENO);
      close(fd);
    }
    // (>) Redirection
    // Create or truncate file
    if (command->redirects[1]){
      int fd = open(command->redirects[1],O_WRONLY | O_CREAT | O_TRUNC,0644); 
      dup2(fd, STDOUT_FILENO);
      close(fd);
    }

    // (>>) Redirection
    // Append output to file
    if (command->redirects[2]){
      int fd = open(command->redirects[2],O_WRONLY | O_CREAT | O_APPEND,0644);
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }
    exec_with_path(command);
  } 
  else {
    // TODO: implement background processes here
    if (command->background != true){
      wait(0); // wait for child process to finish
    }
    return SUCCESS;
  }
}

void exec_with_path(struct command_t *command) {
 //MANUAL PATH RESOLUTION
    char *path = getenv("PATH");
    int path_len = strlen(path) + 1;
    char path_copied[4096]; // Path is copied not to modify original file
    strncpy(path_copied, path, path_len);
    
    char *dir = strtok(path_copied, ":");
    char full_path[4096];

    // Try each directory in PATH
    while (dir != NULL) {
      full_path[0] = '\0';
      strcat(full_path, dir);
      strcat(full_path, "/");
      strcat(full_path, command->name);
      // Try executing constructed path
      execv(full_path, command->args);
      dir = strtok(NULL, ":");
    }
    printf("-%s: %s: command not found\n", sysname, command->name);
    exit(127);
}

int main() {
  while (1) {
    struct command_t *command =
        (struct command_t *)malloc(sizeof(struct command_t));
    memset(command, 0, sizeof(struct command_t)); // set all bytes to 0

    int code;
    code = prompt(command);
    if (code == EXIT)
      break;

    code = process_command(command);
    if (code == EXIT)
      break;

    free_command(command);
  }

  printf("\n");
  return 0;
}
