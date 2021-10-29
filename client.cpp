#include "client.h"

/*
usage: client [ <option> ... ] <command> [<args>] ...

<option> is one of

  -a <addr>, --address <addr>
     Server hostname or address to connect to
  -p <port>, --port <port>
     Server port to connect to
  --help, -h
     Show this help
  --
     Do not treat any remaining argument as a switch (at this level)

 Multiple single-letter switches can be combined after
 one `-`. For example, `-h-` is the same as `-h --`.
 Supported commands:
   register <username> <password>
   login <username> <password>
   list
   send <recipient> <subject> <body>
   fetch <id>
   logout
*/

#define MAXDATASIZE 32818 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    // int sockfd, numbytes;  
    // char buf[MAXDATASIZE];
    // struct addrinfo hints, *server_info, *p;
    // int rv;
    // char s[INET6_ADDRSTRLEN];

    parseargs(argc, argv);

    // //* IP setup
    // memset(&hints, 0, sizeof hints);
    // hints.ai_family = AF_UNSPEC; //* IPv4 or IPv6
    // hints.ai_socktype = SOCK_STREAM; //* TCP

    // if ((rv = getaddrinfo(args.addr.c_str(), args.port.c_str(), &hints, &server_info)) != 0) {
    //     fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    //     return 1;
    // }

    // // loop through all the results and connect to the first we can
    // for(p = server_info; p != NULL; p = p->ai_next) {
    //     sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    //     //* invalid socket, check next list value
    //     if (sockfd == -1) {
    //         perror("client: socket");
    //         continue;
    //     }
    //     //* unable to connect, check next list value
    //     if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
    //         close(sockfd);
    //         perror("client: connect");
    //         continue;
    //     }
    //     break;
    // }

    // if (p == NULL) {
    //     fprintf(stderr, "Client failed to connect to the server.\n");
    //     return 2;
    // }

    // freeaddrinfo(server_info); //* connected - free the structure with server info

    std::string message = get_message(argc, argv);
    printf("%s\n", args.addr.c_str());
    printf("%s\n", args.port.c_str());
    printf("%s\n", message.c_str());
    
    // if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
    //     perror("recv");
    //     exit(1);
    // }

    // buf[numbytes] = '\0';

    // printf("client: received '%s'\n",buf);

    // close(sockfd);

    return 0;
}


void parseargs(int argc, char** argv) {
    int arg;
    extern char *optarg;

    //! arguments count check
    if (argc < 2) {
        fprintf(stderr, "Not enough arguments. See --help.");
        exit(1);
    }

    //* argument parsing
    while (1) {
        static struct option long_options[] = {
                {"address", 1,  0, 'a'},
                {"port", 1,  0, 'p'},
                {"help", 0, 0, 'h'},
                {0, 0, 0, 0}
        };
        int index = 0;
        arg = getopt_long(argc, argv, "a:p:h", long_options, &index);
        if (arg == -1) {
            // end of arguments
            break;
        }
        switch (arg) {
            case 'a':
                args.addr = optarg;
                break;
            case 'p':
                args.port = optarg; 
                break;
            case 'h':
                p_help();
                break;
            case '?':
                break;
        }
    }

    //* no command
    if (optind >= argc) {
        fprintf(stderr, "Invalid command. See --help.\n");
        exit(1);
    }

}

void p_help() {
    printf("usage: client [ <option> ... ] <command> [<args>] ... \n <option> is one of -a <addr>, --address <addr>\n");
    printf("Server hostname or address to connect to\n-p <port>, --port <port>\n -p <port>, --port <port>\nServer port to connect to\n--help, -h\nShow this help\n");
    printf("Multiple single-letter switches can be combined after\none `-`. For example, `-h-` is the same as `-h --`.\n");
    printf("\nSupported commands:\nregister <username> <password>\nlogin <username> <password>\nlist\nsend <recipient> <subject> <body>\nfetch <id>\nlogout\n");
    exit(0);
}

std::string get_message(int argc, char** argv) {
    std::string msg;
    std::string command = argv[optind];
    
    if (command == "register" || command == "login") {
        if (argc != optind + 3) { //* 2 arguments + 1 (index -> count)
            return "";
        }
        std::string nickname = argv[++optind];
        std::string password = encoding::Base64::Encode(argv[++optind]);
        msg = command + " \"" + nickname + "\" \"" + password + "\"";

    } else if (command == "list" or command == "logout") {
        if (argc != optind + 1) { //* 0 arguments + 1 (index -> count)
            return "";
        }
        std::string token = get_token();
        msg = command + " " + token;
        //* remove file with current user's token
        if (command == "logout") {
            std::remove("login-token.txt");
        }

    } else if (command == "fetch") {
        if (argc != optind + 2) { //* 1 argument + 1 (index -> count)
            return "";
        }
        std::string msg_id = argv[++optind];
        std::string token = get_token();
        msg = command + " " + token + " " + msg_id;

    } else if (command == "send") {
        if (argc != optind + 4) { //* 3 arguments + 1 (index -> count)
            return "";
        }
        std::string token = get_token();
        std::string recipient = argv[++optind];
        std::string subject = argv[++optind];
        std::string body = argv[++optind];
        msg = command + " " + token + " \"" + recipient + "\" \"" + subject + "\" \"" + body + "\"";

    } else {
        //! invalid command
        return "";
    }
    return msg;
}

int set_token(std::string token) {
    std::ofstream file("login-token.txt"); //* write mode
    if (file.fail()) {
        return 1;
    }
    file << token;
    file.close();
    return 0;
}

std::string get_token() {
    std::string token;
    std::ifstream file("login-token.txt"); //* read mode
    if (file.fail()) {
        return "\"\"";
    }
    file >> token;
    file.close();
    if (token == "") { token = "\"\""; };
    return token;
}
