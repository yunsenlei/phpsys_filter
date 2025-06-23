provider secex{
    probe request__startup(char* request_file, char* request_uri, char* request_method);
    probe request__shutdown();
    probe function_execute(char *request_file, char *function_name, int lineno);
}