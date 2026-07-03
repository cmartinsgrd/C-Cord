/*
 * ============================================================================
 * SERVER_ETAPA3.C — Servidor C-Cord completo (F3-F10, ligação persistente)
 * ============================================================================
 *
 * Evolução do skeleton: agora com autenticação obrigatória por sessão,
 * todos os comandos da Etapa 2 portados, e canais (F10).
 *
 * MUDANÇAS DE PROTOCOLO FACE À ETAPA 2 (documentar no relatório):
 *
 *   1. Ligação persistente: o cliente liga-se UMA VEZ e mantém o socket
 *      aberto durante toda a sessão (antes: 1 ligação nova por comando).
 *
 *   2. Identidade de sessão: depois de AUTH ter sucesso, o servidor guarda
 *      username/role associados ao socket (cliente_t). Comandos deixam de
 *      precisar de repetir o username:
 *        Etapa 2:  SEND_MSG <dest> <from> <msg>
 *        Etapa 3:  SEND_MSG <dest> <msg>          (from = sessão actual)
 *
 *   3. Comandos exigem autenticação prévia, excepto AUTH e REGISTER.
 *
 *   4. Mensagens etiquetadas (ver protocolo.h: enviar_tagged):
 *        RESP:<conteudo>            → resposta a um comando enviado por mim
 *        SYS:<conteudo>             → notificação do sistema (entrar/sair canal)
 *        CHAT:<canal>:<user>:<msg>  → mensagem de chat em tempo real (F9)
 *
 *   5. F10 — Canais: comando JOIN <canal> muda o canal do cliente; CHAT <msg>
 *      é difundido (broadcast) só a quem está no MESMO canal.
 *
 * Compilação: gcc -Wall -Wextra -o server_etapa3 server_etapa3.c protocolo.c db.c
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "protocolo.h"
#include "db.h"
#include "crypto.h"

static cliente_t clientes[MAX_CLIENTS];
static fd_set    master_set;
static int       fd_max;

/* ============================================================================
 * FUNÇÃO: inicializar_clientes()
 * ============================================================================ */
static void inicializar_clientes(void) 
{
    for (int i = 0; i < MAX_CLIENTS; i++) 
    {
        clientes[i].fd = -1;
        clientes[i].buffer_len = 0;
        clientes[i].autenticado = 0;
        clientes[i].username[0] = '\0';
        clientes[i].role[0] = '\0';
        strcpy(clientes[i].canal, CANAL_OMISSAO);
    }
}

static int encontrar_slot_livre(void) 
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clientes[i].fd == -1) return i;
    return -1;
}

/* ============================================================================
 * FUNÇÃO: broadcast_canal()
 * Envia uma mensagem (já com tag, ex: "CHAT:geral:admin:ola" — mas AINDA
 * em texto simples, por cifrar) a todos os clientes autenticados do
 * mesmo canal, excepto 'excluir_fd'.
 *
 * Etapa 4 (F11/F12): cada ligação tem a SUA PRÓPRIA chave (derivada do
 * handshake DH dessa ligação especificamente). Por isso não é possível
 * cifrar a mensagem uma vez e reencaminhá-la tal-e-qual para todos —
 * tem de se cifrar UMA VEZ POR DESTINATÁRIO, com a chave de cada um.
 * ============================================================================ */
static void broadcast_canal(const char *canal, const char *linha_tagged_plain, int excluir_fd) 
{
    for (int i = 0; i < MAX_CLIENTS; i++) 
    {
        if (clientes[i].fd == -1) continue;
        if (!clientes[i].autenticado) continue;
        if (clientes[i].fd == excluir_fd) continue;
        if (strcmp(clientes[i].canal, canal) != 0) continue;
        enviar_linha_cifrada(clientes[i].fd, linha_tagged_plain, clientes[i].chave_simetrica);
    }
}

static void remover_cliente(int indice) 
{
    char msg[128];
    snprintf(msg, sizeof(msg), "Cliente desligado: '%s' (fd=%d)",
             clientes[indice].username[0] ? clientes[indice].username : "(nao autenticado)",
             clientes[indice].fd);
    guardar_log(msg, 0);

    if (clientes[indice].autenticado) 
    {
        char sys_msg[96];
        snprintf(sys_msg, sizeof(sys_msg), "* %s saiu (desligou-se)", clientes[indice].username);
        char framed[160];
        snprintf(framed, sizeof(framed), "SYS:%s", sys_msg);
        broadcast_canal(clientes[indice].canal, framed, clientes[indice].fd);
    }

    FD_CLR(clientes[indice].fd, &master_set);
    close(clientes[indice].fd);
    clientes[indice].fd = -1;
    clientes[indice].buffer_len = 0;
    clientes[indice].autenticado = 0;
    clientes[indice].username[0] = '\0';
    strcpy(clientes[indice].canal, CANAL_OMISSAO);
}

/* ============================================================================
 * FUNÇÃO: desconectar_sessao_ativa()
 * ============================================================================
 *
 * Se 'username' tiver uma ligação autenticada neste momento, avisa-o do
 * motivo (tag SYS:, já tratada no cliente) e termina-lhe a sessão de
 * imediato — usado quando um admin elimina ou inativa a conta de alguém
 * que ainda está ligado, para que o acesso não continue válido até essa
 * pessoa se desligar por vontade própria.
 * ============================================================================ */
static void desconectar_sessao_ativa(const char *username, const char *motivo) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clientes[i].fd == -1 || !clientes[i].autenticado) continue;
        if (strcmp(clientes[i].username, username) != 0) continue;
        enviar_tagged_cifrada(clientes[i].fd, "SYS", motivo, clientes[i].chave_simetrica);
        remover_cliente(i);
        break;
    }
}

/* ============================================================================
 * FUNÇÃO: processar_comando()
 * ============================================================================
 *
 * Dispatcher central. Recebe a linha já extraída (sem '\n') e o índice do
 * cliente que a enviou. Responde sempre com enviar_tagged(fd, "RESP", ...),
 * excepto para CHAT/JOIN que também fazem broadcast.
 * ============================================================================ */
static void processar_comando(int indice, char *linha) 
{
    cliente_t *cli = &clientes[indice];
    char resposta[BUF_SIZE] = "";
    char log_msg[BUF_SIZE]  = "";
    int  log_type           = 0;

    total_pedidos++;

    /* ---- Comandos permitidos SEM autenticação ---- */

    if (strncmp(linha, "AUTH ", 5) == 0) 
    {
        char u[50] = "", p[50] = "", r[20] = "";
        sscanf(linha + 5, "%49s %49s", u, p);
        int result = check_auth(u, p, r);

        if (result == 1) 
        {
            cli->autenticado = 1;
            strncpy(cli->username, u, MAX_USERNAME - 1);
            strncpy(cli->role, r, MAX_ROLE - 1);
            strcpy(cli->canal, CANAL_OMISSAO);

            sprintf(resposta, "AUTH_SUCCESS:%s", r);
            sprintf(log_msg, "Login com Sucesso!: '%s' (%s)", u, r); log_type = 1;
        } 
        else if (result == -1) 
        {
            strcpy(resposta, "AUTH_PENDING");
            sprintf(log_msg, "Login bloqueado (PENDING): '%s'", u); log_type = 3;
        } 
        else if (result == -2) 
        {
            strcpy(resposta, "AUTH_INACTIVE");
            sprintf(log_msg, "Login bloqueado (INACTIVE): '%s'", u); log_type = 3;
        } 
        else 
        {
            strcpy(resposta, "AUTH_FAIL");
            sprintf(log_msg, "Login FALHOU: '%s'", u); log_type = 3;
        }
        enviar_tagged_cifrada(cli->fd, "RESP", resposta, cli->chave_simetrica);
        guardar_log(log_msg, log_type);
        return;
    }

    if (strncmp(linha, "REGISTER ", 9) == 0) 
    {
        char u[50] = "", p[50] = "";
        sscanf(linha + 9, "%49s %49s", u, p);
        register_user(u, p, resposta);
        sprintf(log_msg, "REGISTER: tentativa para '%s'", u); log_type = 1;
        enviar_tagged_cifrada(cli->fd, "RESP", resposta, cli->chave_simetrica);
        guardar_log(log_msg, log_type);
        return;
    }

    /* ---- A partir daqui, TUDO exige autenticação ---- */
    if (!cli->autenticado) 
    {
        enviar_tagged_cifrada(cli->fd, "RESP", "ERRO: Tens de autenticar primeiro (AUTH <user> <pass>).", cli->chave_simetrica);
        return;
    }

    /* ---- GET_INFO ---- */
    if (strcmp(linha, "GET_INFO") == 0) 
    {
        int up = (int)difftime(time(NULL), start_time);
        sprintf(resposta,
                "C-Cord Server v%s | Uptime: %02dh:%02dm:%02ds | Pedidos: %d | Clientes ligados: -",
                VERSAO_SERVIDOR, up / 3600, (up % 3600) / 60, up % 60, total_pedidos);
        log_type = 0;
    }
    /* ---- ECHO ---- */
    else if (strncmp(linha, "ECHO ", 5) == 0) 
    {
        sprintf(resposta, "Servidor Ecoa: %s", linha + 5);
        log_type = 0;
    }
    /* ---- LIST_ALL ---- */
    else if (strcmp(linha, "LIST_ALL") == 0) 
    {
        list_all(resposta);
        log_type = 0;
    }
    /* ---- LIST_PENDING ---- */
    else if (strcmp(linha, "LIST_PENDING") == 0)
    {
        list_pending(resposta);
        log_type = 0;
    }
    /* ---- LIST_ONLINE (usernames autenticados neste momento, separados por vírgula) ---- */
    else if (strcmp(linha, "LIST_ONLINE") == 0)
    {
        resposta[0] = '\0';
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clientes[i].fd == -1 || !clientes[i].autenticado) continue;
            if (resposta[0] != '\0') strcat(resposta, ",");
            strcat(resposta, clientes[i].username);
        }
        log_type = 0;
    }
    /* ---- CHECK_INBOX (username vem da sessão, já não é parâmetro) ---- */
    else if (strcmp(linha, "CHECK_INBOX") == 0) 
    {
        check_inbox(cli->username, resposta);
        log_type = 0;
    }
    /* ---- GET_CONVERSATION <partner>  (historico bidirecional com 'partner') ---- */
    else if (strncmp(linha, "GET_CONVERSATION ", 17) == 0)
    {
        char partner[50] = "";
        sscanf(linha + 17, "%49s", partner);
        get_conversation(cli->username, partner, resposta);
        log_type = 0;
    }
    /* ---- CHECK_USER_ID <id>  (existe conta com este ID? devolve o username) ---- */
    else if (strncmp(linha, "CHECK_USER_ID ", 14) == 0)
    {
        int alvo_id = atoi(linha + 14);
        char username_alvo[50] = "";
        if (!obter_username_por_id(alvo_id, username_alvo))
            strcpy(resposta, "USER_ID_NOT_FOUND");
        else if (strcmp(username_alvo, cli->username) == 0)
            strcpy(resposta, "USER_ID_SELF");
        else if (is_admin(username_alvo))
            strcpy(resposta, "USER_ID_ADMIN");
        else
            sprintf(resposta, "USER_ID_FOUND:%s", username_alvo);
        log_type = 0;
    }
    /* ---- SEND_MSG <dest> <msg>  (from = sessão actual) ---- */
    else if (strncmp(linha, "SEND_MSG ", 9) == 0)
    {
        char dest[50] = "", msg[400] = "";
        sscanf(linha + 9, "%49s %399[^\n]", dest, msg);
        send_msg(dest, cli->username, msg, resposta);

        /* Se o destinatario estiver ligado agora, empurra-se a mensagem de
         * imediato (tag DM) para a conversa em tempo real — o inbox.txt
         * guardado por send_msg() continua a ser a fonte de verdade para
         * quando o destinatario nao esta online ou reabre a conversa mais tarde. */
        if (strncmp(resposta, "MSG_SENT", 8) == 0)
        {
            for (int i = 0; i < MAX_CLIENTS; i++)
            {
                if (clientes[i].fd == -1 || !clientes[i].autenticado) continue;
                if (strcmp(clientes[i].username, dest) != 0) continue;
                char dm_conteudo[460];
                snprintf(dm_conteudo, sizeof(dm_conteudo), "%s:%s", cli->username, msg);
                enviar_tagged_cifrada(clientes[i].fd, "DM", dm_conteudo, clientes[i].chave_simetrica);
                break;
            }
        }
        sprintf(log_msg, "SEND_MSG: de '%s' para '%s'", cli->username, dest); log_type = 1;
    }
    /* ---- APPROVE_USER <target> ---- */
    else if (strncmp(linha, "APPROVE_USER ", 13) == 0) 
    {
        char target[50] = "";
        sscanf(linha + 13, "%49s", target);
        approve_user(cli->username, target, resposta);
        sprintf(log_msg, "APPROVE_USER: '%s' por '%s'", target, cli->username); log_type = 1;
    }
    /* ---- SUSPEND_USER <target> ---- */
    else if (strncmp(linha, "SUSPEND_USER ", 13) == 0)
    {
        char target[50] = "";
        sscanf(linha + 13, "%49s", target);
        char username_alvo[50] = "";
        obter_username_por_id(atoi(target), username_alvo);
        suspend_user(cli->username, target, resposta);
        if (username_alvo[0] && strncmp(resposta, "SUSPEND_OK", 10) == 0 && strstr(resposta, "INACTIVE"))
            desconectar_sessao_ativa(username_alvo, "A tua conta foi inativada por um administrador. Sessao terminada.");
        sprintf(log_msg, "SUSPEND_USER: '%s' por '%s'", target, cli->username); log_type = 1;
    }
    /* ---- DELETE_USER <target> ---- */
    else if (strncmp(linha, "DELETE_USER ", 12) == 0)
    {
        char target[50] = "";
        sscanf(linha + 12, "%49s", target);
        char username_alvo[50] = "";
        obter_username_por_id(atoi(target), username_alvo);
        delete_user(cli->username, target, resposta);
        if (username_alvo[0] && strncmp(resposta, "DELETE_OK", 9) == 0)
            desconectar_sessao_ativa(username_alvo, "A tua conta foi eliminada por um administrador. Sessao terminada.");
        sprintf(log_msg, "DELETE_USER: '%s' por '%s'", target, cli->username); log_type = 1;
    }
    /* ---- CHANGE_PASSWORD <nova_pass>  (username = sessao actual) ---- */
    else if (strncmp(linha, "CHANGE_PASSWORD ", 16) == 0)
    {
        char nova_pass[50] = "";
        sscanf(linha + 16, "%49s", nova_pass);
        update_password(cli->username, nova_pass, resposta);
        sprintf(log_msg, "CHANGE_PASSWORD: '%s' alterou a password", cli->username); log_type = 1;
    }
    /* ---- VIEW_LOGS ---- */
    else if (strcmp(linha, "VIEW_LOGS") == 0)
    {
        view_logs(cli->username, resposta);
        log_type = 0;
    }
    /* ---- JOIN <canal>  (F10) ---- */
    else if (strncmp(linha, "JOIN ", 5) == 0) 
    {
        char novo_canal[MAX_CANAL_NOME] = "";
        sscanf(linha + 5, "%31s", novo_canal);
        if (strlen(novo_canal) == 0) 
        {
            strcpy(resposta, "ERRO: Indica o nome do canal. Ex: JOIN linux");
        } 
        else if (strcmp(novo_canal, cli->canal) == 0) 
        {
            sprintf(resposta, "JOIN_OK: j´s est´ss no canal #%s", novo_canal);
        } else 
        {
            char saida_msg[96], entrada_msg[96], saida_framed[160], entrada_framed[160];

            snprintf(saida_msg, sizeof(saida_msg), "* %s saiu para #%s", cli->username, novo_canal);
            snprintf(saida_framed, sizeof(saida_framed), "SYS:%s", saida_msg);
            broadcast_canal(cli->canal, saida_framed, cli->fd);

            strncpy(cli->canal, novo_canal, MAX_CANAL_NOME - 1);
            cli->canal[MAX_CANAL_NOME - 1] = '\0';

            snprintf(entrada_msg, sizeof(entrada_msg), "* %s entrou no canal", cli->username);
            snprintf(entrada_framed, sizeof(entrada_framed), "SYS:%s", entrada_msg);
            broadcast_canal(cli->canal, entrada_framed, cli->fd);

            sprintf(resposta, "JOIN_OK: estás agora no canal #%s", novo_canal);
        }
        log_type = 0;
    }
    /* ---- CHAT <msg>  (F9 — broadcast em tempo real, só no canal actual) ---- */
    else if (strncmp(linha, "CHAT ", 5) == 0) 
    {
        const char *msg = linha + 5;
        char framed[LINHA_MAX + 96];
        snprintf(framed, sizeof(framed), "CHAT:%s:%s:%s", cli->canal, cli->username, msg);
        broadcast_canal(cli->canal, framed, cli->fd);
        /* Sem RESP — o próprio cliente já mostra localmente o que escreveu */
        return;
    }
    /* ---- WHOAMI ---- */
    else if (strcmp(linha, "WHOAMI") == 0) 
    {
        sprintf(resposta, "Username: %s | Role: %s | Canal: #%s",
                cli->username, cli->role, cli->canal);
        log_type = 0;
    }
    /* ---- LIST_CANAL  (F15 extra — quem esta no meu canal agora) ---- */
    else if (strcmp(linha, "LIST_CANAL") == 0) 
    {
        char temp[128];
        snprintf(resposta, BUF_SIZE, "=== UTILIZADORES EM #%s ===\n", cli->canal);
        int count = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) 
        {
            if (clientes[i].fd == -1) continue;
            if (!clientes[i].autenticado) continue;
            if (strcmp(clientes[i].canal, cli->canal) != 0) continue;
            snprintf(temp, sizeof(temp), " - %s (%s)%s\n",
                     clientes[i].username, clientes[i].role,
                     (clientes[i].fd == cli->fd) ? "  <- tu" : "");
            strncat(resposta, temp, BUF_SIZE - strlen(resposta) - 1);
            count++;
        }
        snprintf(temp, sizeof(temp), "Total: %d utilizador(es)\n", count);
        strncat(resposta, temp, BUF_SIZE - strlen(resposta) - 1);
        log_type = 0;
    }
    /* ---- CRYPTO_XOR <texto>  (F13 — 2a cifra simetrica) ---- */
    else if (strncmp(linha, "CRYPTO_XOR ", 11) == 0) 
    {
        if (!is_admin(cli->username)) 
        {
            strcpy(resposta, "ERRO: Comando reservado a administradores.");
        } 
        else 
        {
            const char *texto = linha + 11;
            size_t tam = strlen(texto);

            unsigned char buffer[LINHA_MAX];
            memcpy(buffer, texto, tam);

            xor_cifrar(buffer, tam, XOR_CHAVE_OMISSAO, XOR_CHAVE_OMISSAO_LEN);
            char hex[LINHA_MAX * 2];
            bytes_para_hex(buffer, tam, hex);

            /* XOR e a sua propria operacao inversa: cifrar de novo decifra */
            xor_cifrar(buffer, tam, XOR_CHAVE_OMISSAO, XOR_CHAVE_OMISSAO_LEN);
            buffer[tam] = '\0';

            snprintf(resposta, BUF_SIZE, "XOR | Original: %.500s | Cifrado (hex): %.2000s | Decifrado: %.500s",
                    texto, hex, (char *)buffer);
        }
        log_type = 0;
    }
    /* ---- CRYPTO_RSA <texto>  (F13 — cifra assimetrica) ---- */
    else if (strncmp(linha, "CRYPTO_RSA ", 11) == 0) 
    {
        if (!is_admin(cli->username)) 
        {
            strcpy(resposta, "ERRO: Comando reservado a administradores.");
        } 
        else 
        {
            const char *texto = linha + 11;
            char cifrado[LINHA_MAX] = "", decifrado[LINHA_MAX] = "";
            char temp[16];
            size_t dpos = 0;

            for (size_t i = 0; texto[i] != '\0' && i < 200; i++) 
            {
                long long c = rsa_cifrar_char((unsigned char)texto[i]);
                long long m = rsa_decifrar_char(c);

                snprintf(temp, sizeof(temp), "%lld ", c);
                strncat(cifrado, temp, sizeof(cifrado) - strlen(cifrado) - 1);
                decifrado[dpos++] = (char)m;
            }
            decifrado[dpos] = '\0';

            snprintf(resposta, BUF_SIZE,
                    "RSA toy (e=%lld,n=%lld) | Original: %.200s | Cifrado: %.3000s| Decifrado: %.200s",
                    RSA_E, RSA_N, texto, cifrado, decifrado);
        }
        log_type = 0;
    }
    /* ---- CRYPTO_HASH <texto>  (F13 — integridade) ---- */
    else if (strncmp(linha, "CRYPTO_HASH ", 12) == 0) 
    {
        if (!is_admin(cli->username)) 
        {
            strcpy(resposta, "ERRO: Comando reservado a administradores.");
        } 
        else 
        {
            const char *texto = linha + 12;
            unsigned int h = hash_fnv1a(texto);
            sprintf(resposta, "HASH (FNV-1a) | Texto: %s | Hash: %08x", texto, h);
        }
        log_type = 0;
    }
    /* ---- CRYPTO_INFO  (F14 — consulta de parametros criptograficos) ---- */
    else if (strcmp(linha, "CRYPTO_INFO") == 0) 
    {
        if (!is_admin(cli->username)) 
        {
            strcpy(resposta, "ERRO: Comando reservado a administradores.");
        } 
        else 
        {
            sprintf(resposta,
                    "=== PARAMETROS CRIPTOGRAFICOS ===\n"
                    "F11 Cifra de sessao: Cesar generalizada (alfabeto imprimivel 32-126)\n"
                    "F12 Troca de chave: Diffie-Hellman | p=%lld | g=%lld\n"
                    "     A tua chave de sessao actual (derivada do DH): %d\n"
                    "F13 2a cifra simetrica: XOR | tamanho da chave: %d bytes\n"
                    "F13 Cifra assimetrica: RSA toy | chave publica (e=%lld, n=%lld)\n"
                    "F13 Hash de integridade: FNV-1a (32 bits)\n",
                    DH_PRIMO, DH_GERADOR, cli->chave_simetrica,
                    XOR_CHAVE_OMISSAO_LEN, RSA_E, RSA_N);
        }
        log_type = 0;
    }
    /* ---- COMANDO DESCONHECIDO ---- */
    else 
    {
        strcpy(resposta, "CMD_INVALID");
        sprintf(log_msg, "Comando desconhecido de '%s': '%s'", cli->username, linha); log_type = 3;
    }

    enviar_tagged_cifrada(cli->fd, "RESP", resposta, cli->chave_simetrica);
    if (log_msg[0]) guardar_log(log_msg, log_type);
}

/* 
* =========================================================================================================
*   MAIN
* =========================================================================================================
*/
int main(void) 
{
    int fd_escuta;
    struct sockaddr_in addr;
    fd_set read_fds;

    start_time = time(NULL);
    inicializar_clientes();

    fd_escuta = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_escuta < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(fd_escuta, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SERVER_PORT);

    if (bind(fd_escuta, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
    {
        perror("bind"); exit(1);
    }
    listen(fd_escuta, 10);

    printf("======================================================================\n");
    printf(" C-CORD SERVER v%s (Etapa 3 — F9/F10) | porto %d | MAX_CLIENTS=%d\n",
           VERSAO_SERVIDOR, SERVER_PORT, MAX_CLIENTS);
    printf("======================================================================\n");
    fflush(stdout);

    guardar_log("Servidor Etapa 3 iniciado e à escuta.", 1);

    FD_ZERO(&master_set);
    FD_SET(fd_escuta, &master_set);
    fd_max = fd_escuta;

    while (1) 
    {
        read_fds = master_set;

        if (select(fd_max + 1, &read_fds, NULL, NULL, NULL) < 0) 
        {
            perror("select");
            continue;
        }

        /* --- Nova ligação --- */
        if (FD_ISSET(fd_escuta, &read_fds)) {
            struct sockaddr_in cli_addr;
            socklen_t tam = sizeof(cli_addr);
            int novo_fd = accept(fd_escuta, (struct sockaddr *)&cli_addr, &tam);

            if (novo_fd >= 0) 
            {
                int slot = encontrar_slot_livre();
                if (slot == -1) 
                {
                    enviar_tagged(novo_fd, "RESP", "ERRO: Servidor cheio. Tenta mais tarde.");
                    close(novo_fd);
                    guardar_log("Ligacao recusada: pool de clientes esgotada.", 3);
                } 
                else 
                {
                    clientes[slot].fd = novo_fd;
                    clientes[slot].buffer_len = 0;
                    clientes[slot].autenticado = 0;
                    clientes[slot].username[0] = '\0';
                    strcpy(clientes[slot].canal, CANAL_OMISSAO);

                    /* Etapa 4 (F12): handshake Diffie-Hellman ANTES de
                     * mais nada — a partir daqui, tudo o resto nesta
                     * ligação vai cifrado com a chave que aqui se deriva. */
                    if (!dh_handshake_servidor(&clientes[slot])) 
                    {
                        guardar_log("Handshake DH falhou — ligacao rejeitada.", 3);
                        close(novo_fd);
                        clientes[slot].fd = -1;
                    } 
                    else 
                    {
                        FD_SET(novo_fd, &master_set);
                        if (novo_fd > fd_max) fd_max = novo_fd;

                        char msg[128];
                        snprintf(msg, sizeof(msg),
                                 "Nova ligacao aceite (fd=%d) de %s | chave DH=%d",
                                 novo_fd, inet_ntoa(cli_addr.sin_addr),
                                 clientes[slot].chave_simetrica);
                        guardar_log(msg, 0);
                    }
                }
            }
        }

        /* --- Dados de clientes existentes --- */
        for (int i = 0; i < MAX_CLIENTS; i++) 
        {
            if (clientes[i].fd == -1) continue;
            if (!FD_ISSET(clientes[i].fd, &read_fds)) continue;

            char temp[BUF_SIZE];
            int n = (int)read(clientes[i].fd, temp, sizeof(temp));

            if (n <= 0) 
            {
                remover_cliente(i);
                continue;
            }

            if (clientes[i].buffer_len + (size_t)n < BUF_SIZE) 
            {
                memcpy(clientes[i].buffer_entrada + clientes[i].buffer_len, temp, (size_t)n);
                clientes[i].buffer_len += (size_t)n;
            } 
            else 
            {
                guardar_log("Buffer de entrada excedido — mensagem descartada.", 3);
                clientes[i].buffer_len = 0;
                continue;
            }

            char linha[LINHA_MAX];
            while (extrair_linha(&clientes[i], linha, sizeof(linha))) 
            {
                cesar_decifrar_texto(linha, clientes[i].chave_simetrica);
                if (strlen(linha) > 0)
                    processar_comando(i, linha);
            }
        }
    }

    close(fd_escuta);
    return 0;
}
