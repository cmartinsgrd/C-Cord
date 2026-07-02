/*
 * ============================================================================
 * SERVIDOR TCP C-CORD — VERSÃO 2.1 (Etapa 2: F3–F8)
 * ============================================================================
 *
 * Descrição:
 *   Servidor TCP que implementa o protocolo C-CORD para autenticação,
 *   gestão de utilizadores, mensageria, e operações administrativas.
 *   Funciona em modelo bloqueante (sequential) — adequado para Etapa 2.
 *   Etapa 3+ requer select() ou threads para multiplex.
 *
 * Compilação: gcc -Wall -Wextra -o server_linux server_linux.c
 * Execução  : ./server_linux
 * Porto     : 10000
 *
 * Bases de Dados (ficheiros locais):
 *   - users.txt  → ID:username:password:ROLE:STATUS (5 campos por linha)
 *   - inbox.txt  → destinatario:remetente:mensagem (mensagens privadas)
 *   - logs.txt   → registo completo de todas as operações com timestamp
 *
 * Protocolo suportado (Etapa 2 — 11 comandos):
 *   AUTH <user> <pass>             → AUTH_SUCCESS:ADMIN | AUTH_SUCCESS:USER |
 *                                     AUTH_FAIL | AUTH_PENDING | AUTH_INACTIVE
 *   GET_INFO                       → versão servidor + uptime + contagem pedidos
 *   ECHO <msg>                     → "Servidor Ecoa: <msg>" (teste latência)
 *   LIST_ALL                       → tabela formatada ID|user|ROLE|STATUS
 *   LIST_PENDING                   → apenas utilizadores com STATUS=PENDING
 *   CHECK_INBOX <user>             → lista de mensagens para utilizador
 *   SEND_MSG <dest> <from> <msg>   → MSG_SENT | MSG_FAIL
 *   REGISTER <user> <pass>         → REGISTER_OK | REGISTER_FAIL
 *   APPROVE_USER <admin> <target>  → APPROVE_OK | APPROVE_FAIL (PENDING → ACTIVE)
 *   SUSPEND_USER <admin> <target>  → SUSPEND_OK | SUSPEND_FAIL (alterna ACTIVE ↔ INACTIVE)
 *   DELETE_USER <admin> <target>   → DELETE_OK | DELETE_FAIL
 *   VIEW_LOGS <admin>              → últimas 50 linhas de logs.txt
 *
 * ============================================================================
 */

/* ============================================================================
 * CABEÇALHOS E BIBLIOTECAS POSIX
 * ============================================================================
 *
 * Explicação de cada include:
 *
 *   - arpa/inet.h      : Funções de conversão (inet_aton, htons, etc.)
 *   - netinet/in.h     : Estruturas de rede (sockaddr_in, INADDR_ANY)
 *   - stdio.h          : Input/output (printf, FILE, fopen, etc.)
 *   - stdlib.h         : Utilitários (exit, malloc, atoi)
 *   - string.h         : Manipulação de strings (strcmp, strcpy, sprintf)
 *   - sys/socket.h     : API de sockets (socket, bind, listen, accept, send, recv)
 *   - sys/types.h      : Tipos POSIX (socklen_t, etc.)
 *   - time.h           : Funções de tempo (time, localtime, strftime)
 *   - unistd.h         : Utilitários POSIX (close, read, write, sleep)
 *
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SLEEP_SEC(s) Sleep((s) * 1000)
    #define CLEAR_SCREEN "cls"
    #define READ_SOCKET(s, buf, len) recv(s, buf, (int)len, 0)
    #define WRITE_SOCKET(s, buf, len) send(s, buf, (int)len, 0)
    #define SETSOCKOPT_VAL(opt) (const char *)&(opt)
    typedef int socklen_t;
#else
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <sys/socket.h>
    
    #define CLOSE_SOCKET(s) close(s)
    #define SLEEP_SEC(s) sleep(s)
    #define CLEAR_SCREEN "clear"
    #define READ_SOCKET(s, buf, len) read(s, buf, len)
    #define WRITE_SOCKET(s, buf, len) write(s, buf, len)
    #define SETSOCKOPT_VAL(opt) &(opt)
#endif

/* ============================================================================
 * CONSTANTES
 * ============================================================================
 *
 * Definições de configuração do servidor:
 *
 *   - SERVER_PORT: Porto TCP onde servidor escuta (10000)
 *   - BUF_SIZE: Tamanho máximo do buffer para comandos e respostas (4096 bytes)
 *   - USERS_FILE: Nome do ficheiro de base de dados de utilizadores
 *   - INBOX_FILE: Nome do ficheiro de caixa de entrada (mensagens)
 *   - LOG_FILE: Nome do ficheiro de registo de atividade
 *   - MAX_USERS: Limite máximo de utilizadores que podem ser carregados em memória
 *
 * ============================================================================
 */

#define SERVER_PORT  10000
#define BUF_SIZE     4096
#define USERS_FILE   "users.txt"
#define INBOX_FILE   "inbox.txt"
#define LOG_FILE     "logs.txt"
#define MAX_USERS    200

/* ============================================================================
 * VARIÁVEIS GLOBAIS (Estado do servidor)
 * ============================================================================
 *
 * Estas variáveis rastreiam o estado global do servidor durante toda
 * a sua execução:
 *
 *   - VERSAO_SERVIDOR: Identificação da versão (ex: "2.1-Etapa2")
 *   - start_time: Timestamp de quando servidor iniciou (para calcular uptime)
 *   - total_pedidos: Contador de todos os pedidos processados (útil para métricas)
 *
 * ============================================================================
 */

const char *VERSAO_SERVIDOR = "2.1-Etapa2";
time_t      start_time;
int         total_pedidos = 0;

/* ============================================================================
 * FUNÇÃO: guardar_log()
 * ============================================================================
 *
 * O que esta função faz:
 *   Guarda uma mensagem no ficheiro de logs com timestamp, e também
 *   imprime na consola com código de cor ANSI conforme o tipo.
 *
 * Para quê é importante:
 *   Auditoria e debugging. Todas as operações ficam registadas.
 *   Permite admin consultar histórico de ações (VIEW_LOGS).
 *   Cores facilitam leitura rápida: verde=OK, vermelho=ERRO, ciano=INFO.
 *
 * Parâmetros:
 *   - mensagem: texto a guardar (ex: "Login OK: 'admin' (ADMIN)")
 *   - tipo: 1=OK (verde), 3=ERRO (vermelho), outro=INFO (ciano)
 *
 * Como funciona passo a passo:
 *   1. Abrir ficheiro logs.txt em modo append (adiciona ao fim)
 *   2. Obter hora/data actual com time() e localtime()
 *   3. Formatar com strftime() em "YYYY-MM-DD HH:MM:SS"
 *   4. Escrever linha: "[timestamp] mensagem"
 *   5. Fechar ficheiro
 *   6. Imprimir na consola com cor apropriada
 *
 * ============================================================================
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
    /* Imprimir na consola com cor */
    if      (tipo == 1) printf(" \033[1;32m[OK]\033[0m    | %s\n", mensagem);
    else if (tipo == 3) printf(" \033[1;31m[ERRO]\033[0m  | %s\n", mensagem);
    else                printf(" \033[1;36m[INFO]\033[0m  | %s\n", mensagem);
}

/* ============================================================================
 * FUNÇÃO: proximo_id()
 * ============================================================================
 *
 * O que esta função faz:
 *   Lê users.txt inteiro, encontra o ID máximo, e devolve ID+1.
 *   Garante que novos utilizadores recebem ID único auto-incrementado.
 *
 * Para quê é importante:
 *   Evita duplicação de IDs (essencial para identificar utilizadores).
 *   Mantém arquivo de utilizadores bem organizado.
 *
 * Valor de retorno: próximo ID disponível (1 se ficheiro vazio)
 *
 * ============================================================================
 */
int proximo_id() {
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

/* ============================================================================
 * FUNÇÃO: desenhar_cabecalho_servidor()
 * ============================================================================
 *
 * O que esta função faz:
 *   Limpa o terminal e desenha o cabeçalho visual do servidor:
 *   - Logo ASCII do C-CORD
 *   - Versão, status (ONLINE), porto, base de dados
 *   - Indicação de que começa a feed de atividade
 *
 * Para quê é importante:
 *   Feedback visual ao utilizador de que servidor está funcional.
 *   Fácil verificação de configuração (porto, ficheiro de BD).
 *
 * ============================================================================
 */
void desenhar_cabecalho_servidor() {
    system(CLEAR_SCREEN);
    printf("\033[1;36m");
    printf("   ____         ____ ___  ____  ____    \n");
    printf("  / ___|       / ___/ _ \\|  _ \\|  _ \\   \n");
    printf(" | |     ____ | |  | | | | |_) | | | |  \n");
    printf(" | |___ |____|| |__| |_| |  _ <| |_| |  \n");
    printf("  \\____|       \\____\\___/|_| \\_\\____/   \n");
    printf("\033[0m\n");
    printf("======================================================================\n");
    printf("         C-CORD SERVER v%s (Etapa 2 — F3..F8)                        \n", VERSAO_SERVIDOR);
    printf("======================================================================\n");
    printf(" STATUS: \033[1;32mONLINE\033[0m | PORTO: %d | BD: %s\n",
           SERVER_PORT, USERS_FILE);
    printf("----------------------------------------------------------------------\n");
    printf(" LIVE FEED DE ATIVIDADE:\n");
}

/* ============================================================================
 * FUNÇÃO: check_auth()
 * ============================================================================
 *
 * O que esta função faz:
 *   Valida as credenciais (username + password) contra users.txt.
 *   Diferencia entre 4 estados: OK, PENDING, INACTIVE, FAIL.
 *
 * Para quê é importante:
 *   Core de autenticação. Garante que só utilizadores ACTIVE podem entrar.
 *   PENDING = aguarda aprovação admin. INACTIVE = suspenso.
 *
 * Parâmetros:
 *   - username: nome do utilizador
 *   - password: password em texto plano (comparação directa)
 *   - role: OUTPUT — string para guardar ADMIN ou USER (se sucesso)
 *
 * Valor de retorno:
 *    1 = AUTH_SUCCESS (credenciais OK e status ACTIVE)
 *   -1 = AUTH_PENDING (credenciais OK mas status PENDING)
 *   -2 = AUTH_INACTIVE (credenciais OK mas status INACTIVE/suspenso)
 *    0 = AUTH_FAIL (username não existe ou password incorreta)
 *
 * Como funciona passo a passo:
 *   1. Abrir users.txt em modo leitura
 *   2. Loop: ler cada linha, fazer parse dos 5 campos
 *   3. Se username e password coincidem:
 *      - Fechar ficheiro
 *      - Verificar status:
 *        * Se PENDING → retorna -1
 *        * Se INACTIVE → retorna -2
 *        * Senão (ACTIVE) → guardar role e retorna 1
 *   4. Se acabou o ficheiro sem encontrar → retorna 0 (FAIL)
 *
 * ============================================================================
 */
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

/* ============================================================================
 * FUNÇÃO: is_admin()
 * ============================================================================
 *
 * O que esta função faz:
 *   Verifica se um utilizador é admin E está ACTIVE.
 *   Usada para autorizar operações administrativas (aprovação, eliminação, etc).
 *
 * Para quê é importante:
 *   Segurança. Só admins podem fazer operações sensíveis.
 *   Bloqueia tentativas de utilizadores comuns ou PENDING.
 *
 * Valor de retorno: 1 se é admin ACTIVE, 0 senão
 *
 * ============================================================================
 */
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

/* ============================================================================
 * FUNÇÃO: list_all()
 * ============================================================================
 *
 * O que esta função faz:
 *   Lista todos os utilizadores em formato tabela formatada com linhas
 *   separadoras e alinhamento de colunas.
 *
 * Saída formatada:
 *   === UTILIZADORES REGISTADOS ===
 *    ID  | Utilizador       | Funcao  | Estado
 *   -----+------------------+---------+----------
 *     1  | admin            | ADMIN   | ACTIVE
 *     2  | user1            | USER    | PENDING
 *    ...
 *   -----
 *    Total: N registo(s)
 *
 * ============================================================================
 */
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
    sprintf(footer, "-----\n Total: %d registo(s)", total);
    strncat(response, footer, BUF_SIZE - strlen(response) - 1);
}

/* ============================================================================
 * FUNÇÃO: list_pending()
 * ============================================================================
 *
 * O que esta função faz:
 *   Lista apenas utilizadores com STATUS=PENDING (aguardando aprovação admin).
 *
 * ============================================================================
 */
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

/* ============================================================================
 * FUNÇÃO: check_inbox()
 * ============================================================================
 *
 * O que esta função faz:
 *   Devolve todas as mensagens destinadas a um utilizador específico.
 *   Formato: "[N] De: remetente → mensagem"
 *
 * Nota importante:
 *   inbox.txt NUNCA deleta mensagens — todas ficam persistidas.
 *   Modelo assíncrono (Etapa 2). Etapa 3+ poderia usar estado "lida".
 *
 * ============================================================================
 */
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
                sprintf(entry, " [%d] De: %s → %s\n", ++count, from, msg);
                strncat(response, entry, BUF_SIZE - strlen(response) - 1);
            }
        }
    }
    fclose(f);

    if (count == 0)
        strncat(response, " (sem mensagens novas)\n",
                BUF_SIZE - strlen(response) - 1);
}

/* ============================================================================
 * FUNÇÃO: send_msg()
 * ============================================================================
 *
 * O que esta função faz:
 *   Envia uma mensagem privada. Verifica se destinatário existe e
 *   guarda a mensagem no ficheiro inbox.txt.
 *
 * Verificações de segurança:
 *   - Destinatário deve existir em users.txt
 *   - Se não existir, retorna MSG_FAIL com motivo
 *   - Não verifica se remetente é válido (cliente tem responsabilidade)
 *
 * ============================================================================
 */
void send_msg(const char *dest, const char *from, const char *msg, char *response) {
    /* Verificar se destinatário existe */
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

    /* Guardar mensagem em inbox.txt */
    f = fopen(INBOX_FILE, "a");
    if (!f) { strcpy(response, "ERRO: Não foi possível guardar mensagem."); return; }
    fprintf(f, "%s:%s:%s\n", dest, from, msg);
    fclose(f);
    sprintf(response, "MSG_SENT: Mensagem entregue na caixa de %s.", dest);
}

/* ============================================================================
 * FUNÇÃO: register_user()
 * ============================================================================
 *
 * O que esta função faz:
 *   Cria novo utilizador com:
 *   - ID auto-incrementado
 *   - Role fixo: USER (não admin)
 *   - Status: PENDING (aguarda aprovação admin antes de poder login)
 *
 * Verificações:
 *   - Username não pode estar duplicado
 *   - Se duplicado, retorna REGISTER_FAIL com motivo
 *
 * ============================================================================
 */
void register_user(const char *username, const char *password, char *response) {
    /* Verificar duplicado */
    FILE *f = fopen(USERS_FILE, "r");
    if (f) {
        char line[256], id[10], u[50];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%9[^:]:%49[^:]", id, u) >= 2) 
            {
                if (strcmp(u, username) == 0) 
                {
                    fclose(f);
                    strcpy(response, "REGISTER_FAIL: Utilizador ja existe.");
                    return;
                }
            }
        }
        fclose(f);
    }

    /* Criar novo registo com próximo ID */
    int novo_id = proximo_id();
    f = fopen(USERS_FILE, "a");
    if (!f) { strcpy(response, "ERRO: Não foi possível aceder ao ficheiro."); return; }
    fprintf(f, "%d:%s:%s:USER:PENDING\n", novo_id, username, password);
    fclose(f);
    sprintf(response,
            "REGISTER_OK: Utilizador '%s' registado (ID=%d). Aguarda aprovacao do administrador.",
            username, novo_id);
}

/* ============================================================================
 * FUNÇÃO: approve_user()
 * ============================================================================
 *
 * O que esta função faz:
 *   Admin aprova utilizador PENDING, mudando status para ACTIVE.
 *   Só depois pode fazer login com sucesso.
 *
 * Verificações:
 *   - Só admin pode executar
 *   - Target deve existir e estar em estado PENDING
 *
 * ============================================================================
 */
void approve_user(const char *admin_user, const char *target, char *response) {
    if (!is_admin(admin_user)) {
        strcpy(response, "APPROVE_FAIL: Sem permissoes de administrador.");
        return;
    }

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) { strcpy(response, "ERRO: Ficheiro nao encontrado."); return; }

    char lines[MAX_USERS][256];
    int  count = 0, found = 0;
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS)
        count++;
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

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

/* ============================================================================
 * FUNÇÃO: suspend_user()
 * ============================================================================
 *
 * O que esta função faz:
 *   Admin alterna status de um utilizador entre ACTIVE ↔ INACTIVE.
 *   Utilizador INACTIVE não consegue fazer login (mesmo com credenciais OK).
 *
 * Restrições de segurança:
 *   - Admin não consegue suspender a si próprio
 *   - Utilizadores PENDING não podem ser suspensos
 *
 * ============================================================================
 */
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

    char lines[MAX_USERS][256];
    int  count = 0, found = 0;
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS)
        count++;
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

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

/* ============================================================================
 * FUNÇÃO: delete_user()
 * ============================================================================
 *
 * O que esta função faz:
 *   Admin remove utilizador permanentemente da base de dados.
 *   Utilizador e todas as suas dados são apagados.
 *
 * Restrições:
 *   - Admin não consegue apagar a si próprio
 *
 * ============================================================================
 */
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

    char lines[MAX_USERS][256];
    int  count = 0, found = 0;
    while (fgets(lines[count], sizeof(lines[count]), f) && count < MAX_USERS) {
        lines[count][strcspn(lines[count], "\n")] = 0;
        count++;
    }
    fclose(f);

    f = fopen(USERS_FILE, "w");
    if (!f) { strcpy(response, "ERRO: Não foi possível actualizar ficheiro."); return; }

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

/* ============================================================================
 * FUNÇÃO: view_logs()
 * ============================================================================
 *
 * O que esta função faz:
 *   Admin consulta ficheiro de logs. Devolve últimas 50 linhas.
 *
 * Verificações:
 *   - Só admin pode aceder
 *   - Se ficheiro vazio/inexistente, mostra mensagem apropriada
 *
 * ============================================================================
 */
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

/* ============================================================================
 * FUNÇÃO PRINCIPAL: main()
 * ============================================================================
 *
 * O que esta função faz:
 *   Loop infinito do servidor:
 *   1. Criar socket TCP
 *   2. Bind ao INADDR_ANY (qualquer interface) e SERVER_PORT
 *   3. Listen para conexões
 *   4. Accept nova conexão (BLOQUEIA até cliente conectar)
 *   5. Ler comando TCP
 *   6. Processar comando de acordo com protocolo
 *   7. Enviar resposta
 *   8. Fechar conexão e voltar ao passo 4
 *
 * Fluxo de sockets TCP:
 *   - socket(): criar descritor de socket
 *   - setsockopt(): permitir reusar porto rapidamente
 *   - bind(): associar socket ao porto 10000
 *   - listen(): ativar modo listen (aceitar conexões)
 *   - accept(): BLOQUEIA até nova conexão TCP chegar
 *   - read(): BLOQUEIA até dados serem recebidos
 *   - escrever resposta com write()
 *   - close(): fechar socket da conexão (main socket fica aberto)
 *
 * Protocolo: modelo sequencial (bloqueante)
 *   - Etapa 2: apenas 1 cliente por vez
 *   - Etapa 3+: usar select() ou threads para multiplex
 *
 * ============================================================================
 */
int main() {
    int fd, client;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];

    start_time = time(NULL);

    #ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            printf("Falha na inicialização do Winsock.\n");
            return 1;
            }
    #endif

    /* PASSO 1: Criar socket TCP */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(-1); }

    /* PASSO 2: Permitir reusar porto (evita "Address already in use") */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_VAL(opt), sizeof(opt));

    /* PASSO 3: Bind ao porto */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SERVER_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(-1);
    }

    /* PASSO 4: Listen */
    listen(fd, 5);

    desenhar_cabecalho_servidor();
    guardar_log("Servidor v2.1 (Etapa 2) iniciado e a escuta.", 1);

    /* ========== LOOP PRINCIPAL ========== */
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t          size = sizeof(cli_addr);

        /* PASSO 5: Accept (BLOQUEIA até conexão) */
        client = accept(fd, (struct sockaddr *)&cli_addr, &size);
        if (client < 0) continue;

        /* PASSO 6: Read (BLOQUEIA até dados) */
        memset(buffer, 0, BUF_SIZE);
        if (READ_SOCKET(client, buffer, BUF_SIZE - 1) <= 0) {
            CLOSE_SOCKET(client);
            continue;
        }

        /* Remove newlines do buffer */
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r'))
            buffer[--len] = '\0';

        char response[BUF_SIZE] = "";
        char log_msg[BUF_SIZE]  = "";
        int  log_type           = 0;

        total_pedidos++;

        /* ========== PROCESSAMENTO DE COMANDOS ========== */

        /* ---- AUTH ---- */
        if (strncmp(buffer, "AUTH ", 5) == 0) {
            char u[50], p[50], r[20] = "";
            sscanf(buffer + 5, "%49s %49s", u, p);
            int result = check_auth(u, p, r);

            if      (result ==  1) { sprintf(response, "AUTH_SUCCESS:%s", r);
                                     sprintf(log_msg, "Login OK: '%s' (%s)", u, r); log_type = 1; }
            else if (result == -1) { strcpy(response, "AUTH_PENDING");
                                     sprintf(log_msg, "Login bloqueado (PENDING): '%s'", u); log_type = 3; }
            else if (result == -2) { strcpy(response, "AUTH_INACTIVE");
                                     sprintf(log_msg, "Login bloqueado (INACTIVE): '%s'", u); log_type = 3; }
            else                   { strcpy(response, "AUTH_FAIL");
                                     sprintf(log_msg, "Login FALHOU: '%s'", u); log_type = 3; }
        }

        /* ---- GET_INFO ---- */
        else if (strcmp(buffer, "GET_INFO") == 0) {
            int up = (int)difftime(time(NULL), start_time);
            sprintf(response,
                    "C-Cord Server v%s | Uptime: %02dh:%02dm:%02ds | Pedidos: %d",
                    VERSAO_SERVIDOR, up/3600, (up%3600)/60, up%60, total_pedidos);
            sprintf(log_msg, "GET_INFO processado"); log_type = 0;
        }

        /* ---- ECHO ---- */
        else if (strncmp(buffer, "ECHO ", 5) == 0) {
            sprintf(response, "Servidor Ecoa: %s", buffer + 5);
            sprintf(log_msg, "ECHO: '%s'", buffer + 5); log_type = 0;
        }

        /* ---- LIST_ALL ---- */
        else if (strcmp(buffer, "LIST_ALL") == 0) {
            list_all(response);
            sprintf(log_msg, "LIST_ALL executado"); log_type = 0;
        }

        /* ---- LIST_PENDING ---- */
        else if (strcmp(buffer, "LIST_PENDING") == 0) {
            list_pending(response);
            sprintf(log_msg, "LIST_PENDING executado"); log_type = 0;
        }

        /* ---- CHECK_INBOX ---- */
        else if (strncmp(buffer, "CHECK_INBOX ", 12) == 0) {
            char user[50];
            sscanf(buffer + 12, "%49s", user);
            check_inbox(user, response);
            sprintf(log_msg, "CHECK_INBOX: '%s'", user); log_type = 0;
        }

        /* ---- SEND_MSG ---- */
        else if (strncmp(buffer, "SEND_MSG ", 9) == 0) {
            char dest[50], from[50], msg[400];
            sscanf(buffer + 9, "%49s %49s %399[^\n]", dest, from, msg);
            send_msg(dest, from, msg, response);
            sprintf(log_msg, "SEND_MSG: de '%s' para '%s'", from, dest); log_type = 1;
        }

        /* ---- REGISTER ---- */
        else if (strncmp(buffer, "REGISTER ", 9) == 0) {
            char u[50], p[50];
            sscanf(buffer + 9, "%49s %49s", u, p);
            register_user(u, p, response);
            sprintf(log_msg, "REGISTER: tentativa para '%s'", u); log_type = 1;
        }

        /* ---- APPROVE_USER ---- */
        else if (strncmp(buffer, "APPROVE_USER ", 13) == 0) {
            char admin[50], target[50];
            sscanf(buffer + 13, "%49s %49s", admin, target);
            approve_user(admin, target, response);
            sprintf(log_msg, "APPROVE_USER: '%s' por '%s'", target, admin); log_type = 1;
        }

        /* ---- SUSPEND_USER ---- */
        else if (strncmp(buffer, "SUSPEND_USER ", 13) == 0) {
            char admin[50], target[50];
            sscanf(buffer + 13, "%49s %49s", admin, target);
            suspend_user(admin, target, response);
            sprintf(log_msg, "SUSPEND_USER: '%s' por '%s'", target, admin); log_type = 1;
        }

        /* ---- DELETE_USER ---- */
        else if (strncmp(buffer, "DELETE_USER ", 12) == 0) {
            char admin[50], target[50];
            sscanf(buffer + 12, "%49s %49s", admin, target);
            delete_user(admin, target, response);
            sprintf(log_msg, "DELETE_USER: '%s' por '%s'", target, admin); log_type = 1;
        }

        /* ---- VIEW_LOGS ---- */
        else if (strncmp(buffer, "VIEW_LOGS ", 10) == 0) {
            char admin[50];
            sscanf(buffer + 10, "%49s", admin);
            view_logs(admin, response);
            sprintf(log_msg, "VIEW_LOGS: por '%s'", admin); log_type = 0;
        }

        /* ---- COMANDO DESCONHECIDO ---- */
        else {
            strcpy(response, "CMD_INVALID");
            strcpy(log_msg, "Comando desconhecido recebido"); log_type = 3;
        }

        guardar_log(log_msg, log_type);
        WRITE_SOCKET(client, response, (int)strlen(response));
        CLOSE_SOCKET(client);
    }

    #ifdef _WIN32
        WSACleanup();
    #endif
    return 0;
}
