//
// Created by ds on 07/10/23.
//

#ifndef PROGRAMMING101_DISPLAY_H
#define PROGRAMMING101_DISPLAY_H

void display(const char *msg);
void process_cd(char *input);
void process_pwd(void);
void process_type(char *input, char *output);
void process_other(char *command, const char *input, const char *output);
int  handle_client(int client_fd);

#endif    // PROGRAMMING101_DISPLAY_H
