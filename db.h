/*
 * ============================================================================
 * DB.H — Funções de acesso a users.txt / inbox.txt / logs.txt
 * ============================================================================
 *
 * Estas funções são as MESMAS da Etapa 2 (server_linux.c), apenas extraídas
 * para um ficheiro próprio. A lógica de negócio não muda com a introdução
 * de select() — só muda COMO o servidor descobre "quem está a falar"
 * (antes vinha sempre como parâmetro no comando, agora vem da sessão
 * autenticada guardada em cliente_t).
 * ============================================================================
 */

#ifndef DB_H
#define DB_H

#include <time.h>
#include "protocolo.h"

extern const char *VERSAO_SERVIDOR;
extern time_t      start_time;
extern int         total_pedidos;

void guardar_log(const char *mensagem, int tipo);
int  proximo_id(void);

/* tipo de retorno de check_auth: 1=OK, -1=PENDING, -2=INACTIVE, 0=FAIL */
int  check_auth(const char *username, const char *password, char *role);
int  is_admin(const char *username);
int  obter_id_por_username(const char *username);

void list_all(char *response);
void list_pending(char *response);
void check_inbox(const char *username, char *response);
void send_msg(const char *dest, const char *from, const char *msg, char *response);
void register_user(const char *username, const char *password, char *response);
void update_password(const char *username, const char *nova_password, char *response);
void approve_user(const char *admin_user, const char *target, char *response);
void suspend_user(const char *admin_user, const char *target, char *response);
void delete_user(const char *admin_user, const char *target, char *response);
void view_logs(const char *admin_user, char *response);

#endif /* DB_H */
