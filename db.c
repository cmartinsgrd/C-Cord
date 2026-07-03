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
#include "crypto.h"

/* ============================================================================
 * FUNÇÃO: hash_password()
 * ============================================================================
 *
 * Etapa 4 (extra ligado ao F13) — em vez de guardar a password em texto
 * simples em users.txt (limitação assinalada desde a Etapa 2), guarda-se
 * o HASH FNV-1a da password. Isto significa que mesmo quem tiver acesso
 * ao ficheiro users.txt não vê a password original — só consegue
 * verificar se uma tentativa de login bate certo com o hash guardado.
 *
 * IMPORTANTE (para o relatório): FNV-1a foi escolhido por já estar
 * implementado para F13 e por ser simples de explicar/defender. NÃO é
 * um hash adequado para passwords em produção (falta salt, é rápido
 * demais — facilita ataques de força bruta). Em produção usar-se-ia
 * bcrypt/argon2. Aqui serve para eliminar passwords em texto simples
 * do ficheiro, que era a limitação mais óbvia identificada.
 * ============================================================================
 */
static void hash_password(const char *password, char *hash_hex_out) 
{
    unsigned int h = hash_fnv1a(password);
    snprintf(hash_hex_out, 9, "%08x", h);   /* 8 digitos hex + '\0' */
}

const char *VERSAO_SERVIDOR = "3.0-Etapa3";
time_t      start_time;
int         total_pedidos = 0;





int proximo_id(void) 
{
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 1;
    char line[256];
    int  max_id = 0, id = 0;
    while (fgets(line, sizeof(line), f)) 
    {
        if (sscanf(line, "%d:", &id) == 1 && id > max_id)
            max_id = id;
    }
    fclose(f);
    return max_id + 1;
}



/* 
* =========================================================================================================
*   USERS AUTHENTICATION
* =========================================================================================================
*/
int check_auth(const char *username, const char *password, char *role) 
{
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { guardar_log("users.txt nao encontrado!", 3); return 0; }

    char hash_recebido[9];
    hash_password(password, hash_recebido);

    char line[256], id[10], u[50], p[50], r[20], s[20];
    while (fgets(line, sizeof(line), f)) 
    {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) 
        {
            if (strcmp(u, username) == 0 && strcmp(p, hash_recebido) == 0) 
            {
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

/* 
* =========================================================================================================
*   IS ADMIN
* =========================================================================================================
*/
int is_admin(const char *username) 
{
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

/* ============================================================================
 * FUNÇÃO: obter_id_por_username()
 * ============================================================================
 *
 * Devolve o ID (inteiro) do utilizador com o username dado, ou -1 se não
 * encontrado. Usado nas verificações de "não podes agir sobre a tua
 * própria conta" em approve_user/suspend_user/delete_user, agora que o
 * alvo dessas operações é identificado por ID e não por username.
 * ============================================================================
 */
int obter_id_por_username(const char *username) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return -1;
    char line[256], id[10], u[50], p[50], r[20], s[20];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(u, username) == 0) {
                fclose(f);
                return atoi(id);
            }
        }
    }
    fclose(f);
    return -1;
}



/* ============================================================================
 * FUNÇÃO: obter_username_por_id()
 * ============================================================================
 *
 * Inverso de obter_id_por_username(): devolve 1 e escreve o username em
 * username_out se existir um utilizador com o ID dado, ou devolve 0 caso
 * contrário. Usado para resolver o ID escolhido pelo utilizador na lista
 * de contactos para o username exigido por SEND_MSG.
 * ============================================================================
 */
int obter_username_por_id(int id_alvo, char *username_out) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;
    char line[256], id[10], u[50], p[50], r[20], s[20];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (atoi(id) == id_alvo) {
                fclose(f);
                strcpy(username_out, u);
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

    char footer[128];
    sprintf(footer, "---------------------------------\n Total: %d registo(s)", total);
    strncat(response, footer, BUF_SIZE - strlen(response) - 1);
}

void list_pending(char *response) 
{
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    strcpy(response,
           "=== UTILIZADORES PENDENTES ===\n"
           " ID  | Utilizador       | Estado   \n"
           "-----+------------------+----------\n");

    char line[256], id[10], u[50], p[50], r[20], s[20];
    int  total = 0;

    while (fgets(line, sizeof(line), f)) 
    {
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) 
        {
            if (strcmp(s, "PENDING") == 0) 
            {
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
    else 
    {
        char footer[64];
        sprintf(footer, "-----\n Total pendentes: %d\n", total);
        strncat(response, footer, BUF_SIZE - strlen(response) - 1);
    }
}



/* ============================================================================
 * FUNÇÃO: get_conversation()
 * ============================================================================
 *
 * Devolve o histórico bidirecional entre 'me' e 'partner': cada linha do
 * inbox.txt (formato ESTADO:dest:from:msg — ESTADO = NOVA/LIDA, ver
 * send_msg()) é classificada como enviada por mim ("S:msg") ou recebida do
 * outro ("R:msg"), preservando a ordem cronológica em que foram gravadas
 * (o ficheiro é sempre append-only).
 *
 * Como efeito secundário, marca como LIDA qualquer mensagem NOVA recebida
 * de 'partner' — abrir a conversa é o que faz a notificação desaparecer
 * da lista de "mensagens novas" da próxima vez que for consultada.
 * ============================================================================
 */
void get_conversation(const char *me, const char *partner, char *response) {
    response[0] = '\0';
    FILE *f = fopen(INBOX_FILE, "r");
    if (!f) return;

    char linhas[MAX_INBOX_FICHEIRO][512];
    int  total = 0;
    while (fgets(linhas[total], sizeof(linhas[total]), f) && total < MAX_INBOX_FICHEIRO) {
        linhas[total][strcspn(linhas[total], "\n")] = 0;
        total++;
    }
    fclose(f);

    int alterado = 0;
    for (int i = 0; i < total; i++) {
        char status[10], dest[50], from[50], msg[400];
        if (sscanf(linhas[i], "%9[^:]:%49[^:]:%49[^:]:%399[^\n]", status, dest, from, msg) != 4)
            continue;

        char entry[512];
        if (strcmp(dest, me) == 0 && strcmp(from, partner) == 0) {
            sprintf(entry, "R:%s\n", msg);
            strncat(response, entry, BUF_SIZE - strlen(response) - 1);
            if (strcmp(status, "NOVA") == 0) {
                snprintf(linhas[i], sizeof(linhas[i]), "LIDA:%s:%s:%s", dest, from, msg);
                alterado = 1;
            }
        } else if (strcmp(dest, partner) == 0 && strcmp(from, me) == 0) {
            sprintf(entry, "S:%s\n", msg);
            strncat(response, entry, BUF_SIZE - strlen(response) - 1);
        }
    }

    if (alterado) {
        f = fopen(INBOX_FILE, "w");
        if (f) {
            for (int i = 0; i < total; i++) fprintf(f, "%s\n", linhas[i]);
            fclose(f);
        }
    }
}

void check_inbox(const char *username, char *response) {
    FILE *f = fopen(INBOX_FILE, "r");
    if (!f) { strcpy(response, "A sua caixa de entrada esta vazia."); return; }

    sprintf(response, "=== CAIXA DE ENTRADA DE %s ===\n", username);
    char line[512], status[10], dest[50], from[50], msg[400];
    int  count = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (sscanf(line, "%9[^:]:%49[^:]:%49[^:]:%399[^\n]", status, dest, from, msg) == 4) {
            if (strcmp(dest, username) == 0) {
                char entry[512];
                sprintf(entry, " [%d] (%s) De: %s -> %s\n", ++count, status, from, msg);
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
    if (!f) { strcpy(response, "ERRO: Não foi possível guardar mensagem."); return; }
    fprintf(f, "NOVA:%s:%s:%s\n", dest, from, msg);
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
    char hash_pw[9];
    hash_password(password, hash_pw);

    f = fopen(USERS_FILE, "a");
    if (!f) { strcpy(response, "ERRO: Não foi possível aceder ao ficheiro."); return; }
    fprintf(f, "%d:%s:%s:USER:PENDING\n", novo_id, username, hash_pw);
    fclose(f);
    sprintf(response,
            "REGISTER_OK: Utilizador '%s' registado (ID=%d). Aguarda aprovacao do administrador.",
            username, novo_id);
}

void update_password(const char *username, const char *nova_password, char *response) {
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
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

    char hash_pw[9];
    hash_password(nova_password, hash_pw);

    for (int i = 0; i < count; i++) {
        char id[10], u[50], p[50], r[20], s[20];
        if (sscanf(lines[i], "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (strcmp(u, username) == 0) {
                fprintf(f, "%s:%s:%s:%s:%s\n", id, u, hash_pw, r, s);
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
        strcpy(response, "PASSWORD_OK: Palavra-passe atualizada com sucesso.");
    else
        strcpy(response, "PASSWORD_FAIL: Utilizador nao encontrado.");
}

void approve_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "APPROVE_FAIL: Sem permissoes de administrador.");
        return;
    }

    int target_id = atoi(target);
    if (target_id <= 0) {
        strcpy(response, "APPROVE_FAIL: ID invalido. Indica um numero (ver coluna ID em LIST_PENDING).");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS_FICHEIRO][256];
    int  count = 0, found = 0;
    char nome_encontrado[50] = "";
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS_FICHEIRO)
        count++;
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

    for (int i = 0; i < count; i++) {
        char id[10], u[50], p[50], r[20], s[20];
        lines[i][strcspn(lines[i], "\n")] = 0;

        if (sscanf(lines[i], "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (atoi(id) == target_id && strcmp(s, "PENDING") == 0) {
                fprintf(f, "%s:%s:%s:%s:ACTIVE\n", id, u, p, r);
                found = 1;
                strcpy(nome_encontrado, u);
            } else {
                fprintf(f, "%s\n", lines[i]);
            }
        } else if (strlen(lines[i]) > 0) {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    if (found)
        sprintf(response, "APPROVE_OK: Utilizador ID=%d (%s) aprovado. Pode agora autenticar.",
                target_id, nome_encontrado);
    else
        sprintf(response, "APPROVE_FAIL: ID=%d nao encontrado ou ja esta activo.", target_id);
}

void suspend_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "SUSPEND_FAIL: Sem permissoes de administrador.");
        return;
    }

    int target_id = atoi(target);
    if (target_id <= 0) {
        strcpy(response, "SUSPEND_FAIL: ID invalido. Indica um numero (ver coluna ID em LIST_ALL).");
        return;
    }
    if (obter_id_por_username(admin_user) == target_id) {
        strcpy(response, "SUSPEND_FAIL: Nao e possivel suspender a propria conta.");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS_FICHEIRO][256];
    int  count = 0, found = 0;
    char nome_encontrado[50] = "";
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS_FICHEIRO)
        count++;
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

    char novo_estado[20] = "";
    for (int i = 0; i < count; i++) {
        char id[10], u[50], p[50], r[20], s[20];
        lines[i][strcspn(lines[i], "\n")] = 0;

        if (sscanf(lines[i], "%9[^:]:%49[^:]:%49[^:]:%19[^:]:%19s", id, u, p, r, s) == 5) {
            if (atoi(id) == target_id && strcmp(s, "PENDING") != 0) {
                const char *ns = (strcmp(s, "ACTIVE") == 0) ? "INACTIVE" : "ACTIVE";
                fprintf(f, "%s:%s:%s:%s:%s\n", id, u, p, r, ns);
                strcpy(novo_estado, ns);
                found = 1;
                strcpy(nome_encontrado, u);
            } else {
                fprintf(f, "%s\n", lines[i]);
            }
        } else if (strlen(lines[i]) > 0) {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    if (found)
        sprintf(response, "SUSPEND_OK: Estado de ID=%d (%s) alterado para %s.",
                target_id, nome_encontrado, novo_estado);
    else
        sprintf(response, "SUSPEND_FAIL: ID=%d nao encontrado ou esta PENDING.", target_id);
}

void delete_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "DELETE_FAIL: Sem permissoes de administrador.");
        return;
    }

    int target_id = atoi(target);
    if (target_id <= 0) {
        strcpy(response, "DELETE_FAIL: ID invalido. Indica um numero (ver coluna ID em LIST_ALL).");
        return;
    }
    if (obter_id_por_username(admin_user) == target_id) {
        strcpy(response, "DELETE_FAIL: Nao e possivel apagar a propria conta de administrador.");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS_FICHEIRO][256];
    int  count = 0, found = 0;
    char nome_encontrado[50] = "";
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS_FICHEIRO) {
        lines[count][strcspn(lines[count], "\n")] = 0;
        count++;
    }
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

    for (int i = 0; i < count; i++) {
        char id[10], u[50];
        if (sscanf(lines[i], "%9[^:]:%49[^:]", id, u) >= 2 && atoi(id) == target_id) {
            found = 1;
            strcpy(nome_encontrado, u);
        } else if (strlen(lines[i]) > 0) {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    if (found)
        sprintf(response, "DELETE_OK: Utilizador ID=%d (%s) removido do sistema.",
                target_id, nome_encontrado);
    else
        sprintf(response, "DELETE_FAIL: ID=%d nao encontrado.", target_id);
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




/* 
* =========================================================================================================
*   GUARDAR LOGS
* =========================================================================================================
*/
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
