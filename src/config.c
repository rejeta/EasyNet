#include "config.h"
#include "toml.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static protocol_t parse_protocol(const char *s)
{
    if (s && strcmp(s, "udp") == 0) return PROTO_UDP;
    return PROTO_TCP;
}

int config_load(const char *filename, app_config_t *out)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "config_load: failed to open %s\n", filename);
        return -1;
    }

    char errbuf[256];
    toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    if (!conf) {
        fprintf(stderr, "config_load: parse error: %s\n", errbuf);
        return -1;
    }

    memset(out, 0, sizeof(*out));

    toml_datum_t mode = toml_string_in(conf, "mode");
    if (!mode.ok) {
        fprintf(stderr, "config_load: missing 'mode'\n");
        toml_free(conf);
        return -1;
    }
    if (strcmp(mode.u.s, "server") == 0) {
        out->is_server = 1;
    } else if (strcmp(mode.u.s, "client") == 0) {
        out->is_server = 0;
    } else {
        fprintf(stderr, "config_load: invalid mode '%s'\n", mode.u.s);
        free(mode.u.s);
        toml_free(conf);
        return -1;
    }
    free(mode.u.s);

    toml_datum_t password = toml_string_in(conf, "password");
    if (password.ok) {
        strncpy(out->password, password.u.s, PASSWORD_MAX_LEN);
        out->password[PASSWORD_MAX_LEN] = '\0';
        free(password.u.s);
    } else {
        fprintf(stderr, "config_load: missing 'password'\n");
        toml_free(conf);
        return -1;
    }

    if (out->is_server) {
        toml_datum_t bind_addr = toml_string_in(conf, "bind_addr");
        if (bind_addr.ok) {
            strncpy(out->bind_addr, bind_addr.u.s, sizeof(out->bind_addr) - 1);
            free(bind_addr.u.s);
        } else {
            strcpy(out->bind_addr, "0.0.0.0");
        }
        toml_datum_t bind_port = toml_int_in(conf, "bind_port");
        if (bind_port.ok) {
            out->bind_port = (uint16_t)bind_port.u.i;
        } else {
            fprintf(stderr, "config_load: missing 'bind_port'\n");
            toml_free(conf);
            return -1;
        }
    } else {
        toml_datum_t server_addr = toml_string_in(conf, "server_addr");
        if (server_addr.ok) {
            strncpy(out->server_addr, server_addr.u.s, sizeof(out->server_addr) - 1);
            free(server_addr.u.s);
        } else {
            fprintf(stderr, "config_load: missing 'server_addr'\n");
            toml_free(conf);
            return -1;
        }
        toml_datum_t server_port = toml_int_in(conf, "server_port");
        if (server_port.ok) {
            out->server_port = (uint16_t)server_port.u.i;
        } else {
            fprintf(stderr, "config_load: missing 'server_port'\n");
            toml_free(conf);
            return -1;
        }

        toml_array_t *tunnels = toml_array_in(conf, "tunnels");
        if (tunnels) {
            int n = toml_array_nelem(tunnels);
            if (n > MAX_TUNNELS) n = MAX_TUNNELS;
            for (int i = 0; i < n; i++) {
                toml_table_t *t = toml_table_at(tunnels, i);
                if (!t) continue;
                tunnel_config_t *tc = &out->tunnels[out->tunnel_count];

                toml_datum_t local_addr = toml_string_in(t, "local_addr");
                if (local_addr.ok) {
                    strncpy(tc->local_addr, local_addr.u.s, sizeof(tc->local_addr) - 1);
                    free(local_addr.u.s);
                } else {
                    strcpy(tc->local_addr, "127.0.0.1");
                }

                toml_datum_t local_port = toml_int_in(t, "local_port");
                if (local_port.ok) {
                    tc->local_port = (uint16_t)local_port.u.i;
                }

                toml_datum_t remote_port = toml_int_in(t, "remote_port");
                if (remote_port.ok) {
                    tc->remote_port = (uint16_t)remote_port.u.i;
                }

                toml_datum_t protocol = toml_string_in(t, "protocol");
                if (protocol.ok) {
                    tc->protocol = parse_protocol(protocol.u.s);
                    free(protocol.u.s);
                } else {
                    tc->protocol = PROTO_TCP;
                }

                out->tunnel_count++;
            }
        }
    }

    toml_free(conf);
    return 0;
}
