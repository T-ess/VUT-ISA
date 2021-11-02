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

int main(int argc, char *argv[])
{
    int sockfd;  
    struct addrinfo hints, *server_info, *p;
    int rv;

    parseargs(argc, argv);

    //* connection setup
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP
    if ((rv = getaddrinfo(args.addr.c_str(), args.port.c_str(), &hints, &server_info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    //* loop through all the results and connect to the first we can
    for(p = server_info; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        //* invalid socket, check next list value
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }
        //* unable to connect, check next list value
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "Client failed to connect to the server.\n");
        return 2;
    }

    //* connected - free the structure with server info
    freeaddrinfo(server_info);

    std::string command = argv[optind];
    std::string message = get_message(argc, argv, command);
    std::string response;

    if (message == "") {
        close(sockfd);
        return 1;
    }

    if (send_data(message, sockfd) != 0) {
        close(sockfd);
        return 2;
    }

    response = receive_data(sockfd);
    if (response == "") {
        close(sockfd);
        return 2;
    }

    //* print response and resolve login tokens
    std::string terminal = terminal_response(response, command);
    printf("%s\n", terminal.c_str());

    close(sockfd);

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

int send_data(std::string message, int sockfd) {
    char buf[MAXDATASIZE];
    int msg_len = message.length();
    int numbytes = 0;
    do {
        message.copy(buf, MAXDATASIZE-1, 0);
        message.erase(0, MAXDATASIZE-1);
        if ((numbytes += send(sockfd, buf, msg_len, 0)) == -1) {
            perror("Error sending the message.\n");
            return 1;
        }
        memset(buf, '\0', MAXDATASIZE);
    } while (numbytes < msg_len);
    return 0;
}

std::string receive_data(int sockfd) {
    char buf[MAXDATASIZE];
    std::string response = "";
    int numbytes = 0;
        do {
            if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
                perror("Error receiving the message.\n");
                return "";
            } else if (numbytes > 0) {
                response += buf;
            }
            memset(buf, '\0', MAXDATASIZE);
        } while (numbytes > 0);
        return response;
}

std::string get_message(int argc, char** argv, std::string command) {
    std::string msg = "(";
    
    if (command == "register" || command == "login") {
        if (argc != optind + 3) { //* 2 arguments + 1 (index -> count)
            return "";
        }
        std::string nickname = char_to_escaped(argv[++optind]);
        std::string password = encoding::Base64::Encode(argv[++optind]);
        msg += command + " \"" + nickname + "\" \"" + password + "\")";

    } else if (command == "list" or command == "logout") {
        if (argc != optind + 1) { //* 0 arguments + 1 (index -> count)
            return "";
        }
        std::string token = get_token();
        msg += command + " " + token + ")";

    } else if (command == "fetch") {
        if (argc != optind + 2) { //* 1 argument + 1 (index -> count)
            return "";
        }
        std::string msg_id = argv[++optind];
        std::string token = get_token();
        msg += command + " " + token + " " + msg_id + ")";

    } else if (command == "send") {
        if (argc != optind + 4) { //* 3 arguments + 1 (index -> count)
            return "";
        }
        std::string token = get_token();
        std::string recipient = char_to_escaped(argv[++optind]);
        std::string subject = char_to_escaped(argv[++optind]);
        std::string body = char_to_escaped(argv[++optind]);
        printf("%s\n", body.c_str());
        msg += command + " " + token + " \"" + recipient + "\" \"" + subject + "\" \"" + body + "\")";

    } else {
        fprintf(stderr, "Invalid command. See --help.\n");
        return "";
    }
    return msg;
}

std::string terminal_response(std::string server_response, std::string command) {
    std::string message, token;
    bool ok = false;
    std::vector<std::string> response_array;

    //* get response state
    std::string state = server_response.substr(0, server_response.find(' '));
    server_response.erase(0, server_response.find(' '));
    if (state == "(ok") {
        message += "SUCCESS: ";
        ok = true;
    } else if (state == "(err") {
        message += "ERROR: ";
    } else {
        fprintf(stderr, "Invalid server response.\n");
        return "";
    }
    
    //* get response according to the command
    if (command == "list") {
        //* get all parts of response as an array
        response_array = split_response(server_response, true);
        message += "\n";
        //* print all messages
        int msg_index = 1;
        for (int i = 1; i < (int)response_array.size(); i+=2) {
            message += std::to_string(msg_index) + ":\n"; // message index
            message += "  From: " + response_array[i] + "\n"; // sender
            message += "  Subject: " + response_array[i+1] + "\n"; // subject
            msg_index++;
        }
    } else if (command == "fetch") {
        //* get all parts of response as an array
        response_array = split_response(server_response, true);
        message += "\n\nFrom: " + response_array[0] + "\n"; // sender
        message += "Subject: " + response_array[1] + "\n\n"; // subject
        message += response_array[2]; // message
    } else {
        //* get all parts of response as an array
        response_array = split_response(server_response, false);
        if (response_array.size() < 1) {
            fprintf(stderr, "Invalid server response.\n");
            return "";
        }
        message += response_array[0];
    }

    //* resolve login token
    if (response_array.size() > 1) {
        token = response_array[1];
    }
    if (resolve_tokens(ok, command, token) != 0) {
        return "";
    }
    
    return message;
}

std::vector<std::string> split_response(std::string server_response, bool list_fetch) {
    size_t pos = 0;
    std::string substring;
    std::vector<std::string> response_array {};
    server_response.pop_back(); // erase )

    server_response = escaped_to_special(server_response);

    while ((pos = server_response.find(" \"")) != std::string::npos) {
        substring = server_response.substr(0, pos);
        if (substring != "") {
            substring.pop_back(); // erase the '"' at the end
            response_array.push_back(substring);
        }
        server_response.erase(0, pos + 2); // 2 characters as delimiter
    }
    server_response.pop_back(); // erase the quote at the end
    response_array.push_back(server_response);

    std::regex list_fetch01 ("\"\\)( )?(\\()?[0-9]*$");
    std::regex list_fetch02 ("^( )*(\\()?(\")?");

    for (int i = 0; i < (int)response_array.size(); i++) {
        response_array[i] = special_to_char(response_array[i]);
        if (list_fetch) {
            response_array[i] = std::regex_replace(response_array[i], list_fetch01, "");
            response_array[i] = std::regex_replace(response_array[i], list_fetch02, "");
        }
    }

    return response_array;
}

std::string replace_all(std::string msg, std::string replaced, std::string replace) {
    size_t index = 0;
    while((index = msg.find(replaced, index)) != std::string::npos) {
        msg.replace(index, replaced.size(), replace);
        index += replace.size();
    }
    return msg;
}

std::string escaped_to_special(std::string input_msg) {
    input_msg = replace_all(input_msg, "\\\\", "<char92>");
    input_msg = replace_all(input_msg, "\\\"", "<char34>");
    input_msg = replace_all(input_msg, "\n", "<char10>");
    return input_msg;
}

std::string special_to_char(std::string input_msg) {
    input_msg = replace_all(input_msg, "<char92>", "\\");
    input_msg = replace_all(input_msg, "<char34>", "\"");
    input_msg = replace_all(input_msg, "<char10>", "\n");
    return input_msg;
}

std::string char_to_escaped(std::string input_msg) {
    input_msg = replace_all(input_msg, "\\", "\\\\");
    input_msg = replace_all(input_msg, "\"", "\\\"");
    input_msg = replace_all(input_msg, "\n", "\\n");
    return input_msg;
}

int resolve_tokens(bool state, std::string command, std::string token) {
    if (state) {
        if (command == "login") {
            if (set_token(token) != 0) {
                return 1;
            }
        } else if (command == "logout") {
            //* remove file with current user's token
            if (std::remove("login-token") != 0) {
                fprintf(stderr, "Error while removing the current login token.\n");
                return 1;
            }
        }
    }
    return 0;
}

int set_token(std::string token) {
    std::ofstream file("login-token"); //* write mode
    if (file.fail()) {
        fprintf(stderr, "Error while saving the login token.\n");
        return 1;
    }
    file << "\"" << token << "\"";
    file.close();
    return 0;
}

std::string get_token() {
    std::string token;
    std::ifstream file("login-token"); //* read mode
    if (file.fail()) {
        fprintf(stderr, "Error while getting the login token.\n");
        return "\"\"";
    }
    file >> token;
    file.close();
    if (token == "") { token = "\"\""; };
    return token;
}
