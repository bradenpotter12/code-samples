//
//  main.cpp
//  UnixShell
//
//  Created by Braden Potter on 2/23/21.
//

#include "shelpers.hpp"


int main(int argc, const char * argv[]) {
    Command command;
    std::string inputLine;
    std::vector<Command> commands;
    
    // Shell Loop
    while (std::getline(std::cin, inputLine)) {
        
        // Causes weird linking errors in terminal
        // Maybe missing header, compiles and runs OK in Xcode
        commands = getCommands(tokenize(inputLine));
        
        // convert command.argv vector to array
        std::vector<const char*> commandArgVec = commands[0].argv;
        char *argv[commandArgVec.size()];
        
        for (int i = 0; i < commandArgVec.size(); i++) {
            argv[i] = const_cast<char*>(commandArgVec[i]);
        }
        
        int pid = fork();
        
        if (pid < 0) {     /* fork a child process           */
            printf("*** ERROR: forking child process failed\n");
            exit(1);
        }
        else if (pid == 0) { // child (new process)
            
            // Call dup2 and check for errors
            if(dup2(commands[0].fdStdout, STDOUT_FILENO) < 0) {
                printf("Unable to duplicate file descriptor.");
                exit(EXIT_FAILURE);
            }
            
            execvp(argv[0], argv);
        }
        else { // parent process
            wait(0);
            
            if (commands[0].fdStdin != 0) {
                std::cout << "in parent, closing fdStdin...\n";
                if (close(commands[0].fdStdin) == -1)
                    std::cerr << "cant close fd0\n";
            }
            if (commands[0].fdStdout != 1) {
                std::cout << "in parent, closing fdStdout...\n";
                if (close(commands[0].fdStdout) == -1)
                    std::cerr << "cant close fd1\n";
            }
        }
    }
    return 0;
}
