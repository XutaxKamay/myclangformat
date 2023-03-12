#include "../includes/inject.h"

char g_dllPath[FILENAME_MAX];

const int str_hex_digits = sizeof(ptr_t) * 2;

void setup_string(string_t* str, size_t maxlen)
{
    str->len    = 0;
    str->maxlen = maxlen;
    str->pc     = (char*)malloc(maxlen);
    memset(str->pc, 0, maxlen);
}

void free_string(string_t* str)
{
    free(str->pc);
}

// Parse proc/pid/maps
void get_remote_lib(const char* lib, pid_t pid, lib_t* result)
{
    // Who knows maybe some actual path makes it that far...
    char maps[FILENAME_MAX], line_buffer[FILENAME_MAX + 0x100];
    char str_base[str_hex_digits];
    int count_hex;
    FILE* file_maps;

    count_hex           = 0;
    file_maps           = NULL;
    result->base_addr.p = NULL;
    sprintf(maps, "/proc/%i/maps", pid);
    file_maps = fopen(maps, "r");

    if (file_maps == NULL)
    {
        goto ret;
    }

    // Find the first occurence, it's usually the base address of the
    // library.
    while (fgets(line_buffer, sizeof(line_buffer), file_maps))
    {
        if (strstr(line_buffer, lib))
        {
            memcpy(str_base, line_buffer, str_hex_digits);
            while (str_base[count_hex] != '-'
                   && count_hex < str_hex_digits)
            {
                count_hex++;
            }

            if ((str_hex_digits - count_hex) > 0)
            {
                memset(str_base + count_hex,
                       '\0',
                       str_hex_digits - count_hex);
            }

#ifndef MX64
            result->base_addr.ui = strtoul(str_base, NULL, 16);
#else
            result->base_addr.ui = strtoull(str_base, NULL, 16);
#endif
            while (line_buffer[count_hex] != '\n')
            {
                // We found a path here;
                if (line_buffer[count_hex] == '/')
                {
                    break;
                }

                count_hex++;
            }

            // We can just copy as the path is the last thing we get on
            // the line.
            strcpy(result->filename.pc, &line_buffer[count_hex]);
            result->filename.len = strlen(result->filename.pc);
            result->filename.len--;

            // Override \n.
            result->filename.pc[result->filename.len] = '\0';
            break;
        }
    }

ret:
    if (file_maps != NULL)
    {
        fclose(file_maps);
    }
}

ptr_u_t find_remote_function(link_map_t* lm, const char* func, pid_t pid)
{
    ptr_u_t result, ptr_sym, ptr_offset;
    lib_t remote_lib, local_lib;
    setup_string(&remote_lib.filename, FILENAME_MAX);
    setup_string(&local_lib.filename, FILENAME_MAX);

    // Sometimes they're just symbolic names.
    realpath(lm->l_name, local_lib.filename.pc);

    result.p = NULL;

    ptr_sym.p = dlsym(lm, func);

    if (ptr_sym.p == NULL)
    {
        ERR("couldn't find function %s in shared lib %s in current "
            "process\n",
            func,
            lm->l_name);
        goto ret;
    }

    ptr_offset.ui = ptr_sym.ui - lm->l_addr;

    get_remote_lib(local_lib.filename.pc, pid, &remote_lib);

    if (remote_lib.base_addr.p == NULL)
    {
        ERR("couldn't find shared lib %s in pid: %i\n", lm->l_name, pid);
        goto ret;
    }

    result.ui = remote_lib.base_addr.ui + ptr_offset.ui;

ret:

    free_string(&remote_lib.filename);
    free_string(&local_lib.filename);

    return result;
}

// TODO: There is still a case where the remote process haven't the
// library loaded.. So we can just use this function to get dlopen and
// load our libs on the remote process!

ptr_u_t get_remote_function(const char* lib, const char* func, pid_t pid)
{
    link_map_t* lm;
    ptr_u_t result;
    lib_t remote_lib;

    setup_string(&remote_lib.filename, FILENAME_MAX);

    result.p = NULL;
    lm       = (link_map_t*)dlopen(NULL, RTLD_NOW);

    // Ignore the current process, it's the first into the list.
    dlclose(lm);

    lm = lm->l_next;

    while (lm != NULL)
    {
        if (lib != NULL)
        {
            if (!strstr(lm->l_name, lib))
            {
                goto next;
            }
        }

        lm     = (link_map_t*)dlopen(lm->l_name, RTLD_NOW);
        result = find_remote_function(lm, func, pid);

        if (result.p != NULL)
        {
            dlclose(lm);
            goto ret;
        }

        dlclose(lm);
    next:
        lm = lm->l_next;
    }

    // Library isn't loaded..
    // We might load it ourselves and try to find it again.
    if (lib != NULL)
    {
        get_remote_lib(lib, pid, &remote_lib);

        if (remote_lib.base_addr.p == NULL)
        {
            // At this point, there is nothing we can do...
            ERR("Couldn't find %s(%s) from remote process...\n",
                lib,
                func);
            goto ret;
        }

        // Okay this is good, now we load it for our current process
        // and we can extract the function address from remote process.
        lm = (link_map_t*)dlopen(remote_lib.filename.pc, RTLD_LAZY);
        if (lm != NULL)
        {
            result.p = dlsym(lm, func);

            if (result.p == NULL)
            {
                ERR("Couldn't find %s(%s) from current process...\n",
                    lib,
                    func);
                goto ret;
            }

            result.ui -= lm->l_addr;
            result.ui += remote_lib.base_addr.ui;
            dlclose(lm);
        }
        else
        {
            // Architecture is maybe not the same... Or something else.
            ERR("Couldn't load %s(%s) from to our process...\n",
                lib,
                func);
            goto ret;
        }
    }

ret:
    free_string(&remote_lib.filename);

    return result;
}

uint8_t create_remote_thread(ptr_u_t thread_parameter,
                             thread_func_t remote_func,
                             pid_t pid)
{
    return 0;
}

int main(int cargs, char** args)
{
    pid_t pid;

    printf("Please enter pid\n");
    scanf("%i", &pid);
    printf("Please enter path of the shared library you want to "
           "inject\n");
    scanf("%s", g_dllPath);

    ptr_u_t ptr_remote_dlopen = get_remote_function("libdl",
                                                    "dlopen",
                                                    pid);

    if (ptr_remote_dlopen.p == NULL)
    {
        printf("Couldn't find dlopen function from pid: %i\n", pid);
        return 0;
    }

    return 0;
}
