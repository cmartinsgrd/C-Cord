/*
 * ============================================================================
 * DB.C — Implementação (idêntica à Etapa 2, ver db.h para explicação)
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "db.h"

const char *VERSAO_SERVIDOR = "3.0-Etapa3";
time_t      start_time;
int         total_pedidos = 0;

void guardar_log(const char *mensagem, int tipo) {
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        char    data[64];
        time_t  agora = time(NULL);
        struct tm *t  = localtime(&agora);
        strftime(data, sizeof(data), "%Y-%m-%d %H:%M:%S", t);
        fprintf(f, "[%s] %s\n", data, mensagem);
        fclose(f);
    }
    if      (tipo == 1) printf(" \033[1;32m[OK]\033[0m    | %s\n", mensagem);
    else if (tipo == 3) printf(" \033[1;31m[ERRO]\033[0m  | %s\n", mensagem);
    else                printf(" \033[1;36m[INFO]\033[0m  | %s\n", mensagem);
    fflush(stdout);
}

int proximo_id(void) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 1;
    char line[256];
    int  max_id = 0, id = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%d:", &id) == 1 && id > max_id)
            max_id = id;
    }
    fclose(f);
    return max_id + 1;
}

int check_auth(const char *username, const char *password, char *role) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { guardar_log("users.txt nao encontrado!", 3); return 0; }

    char line[256], id[10], u[50], p[50], r[20], s[20];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(u, username) == 0 && strcmp(p, password) == 0) {
                fclose(f);
                if (strcmp(s, "PENDING")  == 0) return -1;
                if (strcmp(s, "INACTIVE") == 0) return -2;
                strcpy(role, r);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

int is_admin(const char *username) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;
    char line[256], id[10], u[50], p[50], r[20], s[20];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(u, username) == 0 && strcmp(r, "ADMIN") == 0 &&
                strcmp(s, "ACTIVE") == 0) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

void list_all(char *response) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro de utilizadores nao encontrado."); return; }

    strcpy(response,
           "=== UTILIZADORES REGISTADOS ===\n"
           " ID  | Utilizador       | Funcao  | Estado   \n"
           "-----+------------------+---------+----------\n");

    char line[256], id[10], u[50], p[50], r[20], s[20];
    int  total = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            char entry[128];
            sprintf(entry, " %-3s | %-16s | %-7s | %s\n", id, u, r, s);
            strncat(response, entry, BUF_SIZE - strlen(response) - 1);
            total++;
        }
    }
    fclose(f);

    char footer[64];
    sprintf(footer, "-----\n Total: %d registo(s)\n", total);
    strncat(response, footer, BUF_SIZE - strlen(response) - 1);
}

void list_pending(char *response) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    strcpy(response,
           "=== UTILIZADORES PENDENTES ===\n"
           " ID  | Utilizador       | Estado   \n"
           "-----+------------------+----------\n");

    char line[256], id[10], u[50], p[50], r[20], s[20];
    int  total = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(s, "PENDING") == 0) {
                char entry[128];
                sprintf(entry, " %-3s | %-16s | %s\n", id, u, s);
                strncat(response, entry, BUF_SIZE - strlen(response) - 1);
                total++;
            }
        }
    }
    fclose(f);

    if (total == 0)
        strncat(response, " (sem utilizadores pendentes)\n",
                BUF_SIZE - strlen(response) - 1);
    else {
        char footer[64];
        sprintf(footer, "-----\n Total pendentes: %d\n", total);
        strncat(response, footer, BUF_SIZE - strlen(response) - 1);
    }
}

void check_inbox(const char *username, char *response) {
    FILE *f = fopen(INBOX_FILE, "r");
    if (!f) { strcpy(response, "A sua caixa de entrada esta vazia."); return; }

    sprintf(response, "=== CAIXA DE ENTRADA DE %s ===\n", username);
    char line[512], dest[50], from[50], msg[400];
    int  count = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (sscanf(line, "%49[^:]:%49[^:]:%399[^\n]", dest, from, msg) == 3) {
            if (strcmp(dest, username) == 0) {
                char entry[512];
                sprintf(entry, " [%d] De: %s -> %s\n", ++count, from, msg);
                strncat(response, entry, BUF_SIZE - strlen(response) - 1);
            }
        }
    }
    fclose(f);

    if (count == 0)
        strncat(response, " (sem mensagens novas)\n",
                BUF_SIZE - strlen(response) - 1);
}

void send_msg(const char *dest, const char *from, const char *msg, char *response) {
    FILE *f = fopen(USERS_FILE, "r");
    int   found = 0;
    if (f) {
        char line[256], id[10], u[50], p[50], r[20], s[20];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
                if (strcmp(u, dest) == 0) { found = 1; break; }
            }
        }
        fclose(f);
    }
    if (!found) {
        sprintf(response, "MSG_FAIL: Utilizador '%s' nao encontrado.", dest);
        return;
    }

    f = fopen(INBOX_FILE, "a");
    if (!f) { strcpy(response, "ERRO: Nao foi possivel guardar mensagem."); return; }
    fprintf(f, "%s:%s:%s\n", dest, from, msg);
    fclose(f);
    sprintf(response, "MSG_SENT: Mensagem entregue na caixa de %s.", dest);
}

void register_user(const char *username, const char *password, char *response) {
    FILE *f = fopen(USERS_FILE, "r");
    if (f) {
        char line[256], id[10], u[50];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%9[^:]:%49[^:]", id, u) >= 2) {
                if (strcmp(u, username) == 0) {
                    fclose(f);
                    strcpy(response, "REGISTER_FAIL: Utilizador ja existe.");
                    return;
                }
            }
        }
        fclose(f);
    }

    int novo_id = proximo_id();
    f = fopen(USERS_FILE, "a");
    if (!f) { strcpy(response, "ERRO: Nao foi possivel aceder ao ficheiro."); return; }
    fprintf(f, "%d:%s:%s:USER:PENDING\n", novo_id, username, password);
    fclose(f);
    sprintf(response,
            "REGISTER_OK: Utilizador '%s' registado (ID=%d). Aguarda aprovacao do administrador.",
            username, novo_id);
}

void approve_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "APPROVE_FAIL: Sem permissoes de administrador.");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS_FICHEIRO][256];
    int  count = 0, found = 0;
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS_FICHEIRO)
        count++;
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Nao foi possivel actualizar ficheiro."); return; }

    for (int i = 0; i < count; i++) {
        char id[10], u[50], p[50], r[20], s[20];
        lines[i][strcspn(lines[i], "\n")] = 0;

        if (sscanf(lines[i], "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(u, target) == 0 && strcmp(s, "PENDING") == 0) {
                fprintf(f, "%s:%s:%s:%s:ACTIVE\n", id, u, p, r);
                found = 1;
            } else {
                fprintf(f, "%s\n", lines[i]);
            }
        } else if (strlen(lines[i]) > 0) {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    if (found)
        sprintf(response, "APPROVE_OK: Utilizador '%s' aprovado. Pode agora autenticar.", target);
    else
        sprintf(response, "APPROVE_FAIL: Utilizador '%s' nao encontrado ou ja esta activo.", target);
}

void suspend_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "SUSPEND_FAIL: Sem permissoes de administrador.");
        return;
    }
    if (strcmp(admin_user, target) == 0) {
        strcpy(response, "SUSPEND_FAIL: Nao e possivel suspender a propria conta.");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS_FICHEIRO][256];
    int  count = 0, found = 0;
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS_FICHEIRO)
        count++;
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Nao foi possivel actualizar ficheiro."); return; }

    char novo_estado[20] = "";
    for (int i = 0; i < count; i++) {
        char id[10], u[50], p[50], r[20], s[20];
        lines[i][strcspn(lines[i], "\n")] = 0;

        if (sscanf(lines[i], "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(u, target) == 0 && strcmp(s, "PENDING") != 0) {
                const char *ns = (strcmp(s, "ACTIVE") == 0) ? "INACTIVE" : "ACTIVE";
                fprintf(f, "%s:%s:%s:%s:%s\n", id, u, p, r, ns);
                strcpy(novo_estado, ns);
                found = 1;
            } else {
                fprintf(f, "%s\n", lines[i]);
            }
        } else if (strlen(lines[i]) > 0) {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    if (found)
        sprintf(response, "SUSPEND_OK: Estado de '%s' alterado para %s.", target, novo_estado);
    else
        sprintf(response, "SUSPEND_FAIL: Utilizador '%s' nao encontrado ou esta PENDING.", target);
}

void delete_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "DELETE_FAIL: Sem permissoes de administrador.");
        return;
    }
    if (strcmp(admin_user, target) == 0) {
        strcpy(response, "DELETE_FAIL: Nao e possivel apagar a propria conta de administrador.");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS_FICHEIRO][256];
    int  count = 0, found = 0;
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS_FICHEIRO) {
        lines[count][strcspn(lines[count], "\n")] = 0;
        count++;
    }
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Nao foi possivel actualizar ficheiro."); return; }

    for (int i = 0; i < count; i++) {
        char id[10], u[50];
        if (sscanf(lines[i], "%9[^:]:%49[^:]", id, u) >= 2 && strcmp(u, target) == 0) {
            found = 1;
        } else if (strlen(lines[i]) > 0) {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    if (found)
        sprintf(response, "DELETE_OK: Utilizador '%s' removido do sistema.", target);
    else
        sprintf(response, "DELETE_FAIL: Utilizador '%s' nao encontrado.", target);
}

void view_logs(const char *admin_user, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "LOGS_FAIL: Sem permissoes de administrador.");
        return;
    }
    FILE *f = fopen(LOG_FILE, "r");
    if (!f) { strcpy(response, "=== LOGS ===\n (ficheiro vazio ou inexistente)\n"); return; }

    strcpy(response, "=== REGISTO DE ATIVIDADE ===\n");
    char line[256];
    int  count = 0;
    char buffer[200][256];
    while (fgets(line, sizeof(line), f) && count < 200)
        strcpy(buffer[count++], line);
    fclose(f);

    int start = (count > 50) ? count - 50 : 0;
    for (int i = start; i < count; i++)
        strncat(response, buffer[i], BUF_SIZE - strlen(response) - 1);
}
