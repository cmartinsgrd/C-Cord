/*
 * ============================================================================
 * PROTOCOLO.H — Definições partilhadas entre servidor e cliente (Etapa 3+)
 * ============================================================================
 *
 * PORQUÊ ESTE FICHEIRO EXISTE:
 *   Nas Etapas 1-2, cada comando abria uma ligação TCP nova, enviava UMA
 *   mensagem, recebia UMA resposta, e fechava. Não havia ambiguidade sobre
 *   "onde acaba a mensagem" — o fecho da ligação marcava o fim.
 *
 *   Na Etapa 3+, a ligação fica aberta durante toda a sessão. Isto introduz
 *   um problema clássico de programação de sockets: o TCP é um STREAM de
 *   bytes, não um stream de "mensagens". Se o servidor enviar duas respostas
 *   seguidas rapidamente, o cliente pode recebê-las coladas numa única
 *   chamada a recv() (ex: "MSG_OK\nLOGS_OK\n"), ou pode receber uma mensagem
 *   partida ao meio (metade agora, metade na próxima recv()).
 *
 *   SOLUÇÃO (framing por delimitador):
 *   Toda a mensagem, em ambos os sentidos, termina com '\n'. Cada lado
 *   mantém um buffer de acumulação por ligação e só processa uma mensagem
 *   quando encontra um '\n' completo no buffer. Texto a seguir ao '\n' fica
 *   guardado para a iteração seguinte.
 *
 * ============================================================================
 */

#ifndef PROTOCOLO_H
#define PROTOCOLO_H

#include <stddef.h>

/* ---------------------------------------------------------------------
 * CONSTANTES DE REDE E CAPACIDADE
 * ---------------------------------------------------------------------
 *
 * MAX_CLIENTS = 50
 *   Decisão de design (não é limite técnico do select()/FD_SETSIZE, que é
 *   tipicamente 1024). Escolhido porque:
 *     - select() percorre TODOS os file descriptors em cada iteração
 *       (complexidade O(n)) — não escala bem para milhares de ligações,
 *       mas 50 é trivial de percorrer em cada ciclo.
 *     - É um valor confortável para demonstração/avaliação em sala de aula
 *       (turma inteira + testes automáticos), sem desperdiçar memória com
 *       uma tabela de clientes desnecessariamente grande.
 *   Justificação a incluir no relatório.
 * --------------------------------------------------------------------- */
#define SERVER_PORT     10000
#define MAX_CLIENTS     50
#define BUF_SIZE        4096
#define LINHA_MAX       4096   /* tamanho máx. de UMA mensagem framed (sem \n) */
#define MAX_CANAL_NOME  32
#define MAX_USERNAME    50
#define MAX_ROLE        20

#define USERS_FILE      "users.txt"
#define INBOX_FILE      "inbox.txt"
#define LOG_FILE        "logs.txt"
#define MAX_USERS_FICHEIRO 200   /* limite de linhas lidas de users.txt em memória (reescrita) */

#define CANAL_OMISSAO   "geral"   /* canal por defeito ao autenticar */

/* ---------------------------------------------------------------------
 * ESTADO DE UM CLIENTE LIGADO (mantido pelo SERVIDOR)
 * ---------------------------------------------------------------------
 *
 * Uma entrada por socket activo. autenticado=0 até AUTH ter sucesso;
 * comandos sensíveis (chat, admin) são recusados antes disso.
 *
 * buffer_entrada / buffer_len: acumulador de framing (ver cabeçalho do
 * ficheiro). Dados parciais (sem '\n' ainda) ficam aqui entre chamadas
 * a select()/recv().
 * --------------------------------------------------------------------- */
typedef struct {
    int    fd;                          /* -1 = slot livre */
    char   username[MAX_USERNAME];
    char   role[MAX_ROLE];
    int    autenticado;                 /* 0/1 */
    char   canal[MAX_CANAL_NOME];       /* canal actual (F10) */

    char   buffer_entrada[BUF_SIZE];    /* acumulador de bytes recebidos */
    size_t buffer_len;                  /* bytes válidos em buffer_entrada */
} cliente_t;

/* ---------------------------------------------------------------------
 * FUNÇÕES DE FRAMING (implementadas em protocolo.c, partilhadas)
 * --------------------------------------------------------------------- */

/* Envia 'msg' pelo socket fd, garantindo terminador '\n'.
 * Devolve 0 em sucesso, -1 em erro. */
int enviar_linha(int fd, const char *msg);

/* Envia uma mensagem ETIQUETADA (tag = "RESP", "SYS" ou "CHAT") ao cliente.
 *
 * PORQUÊ ETIQUETAS:
 *   Numa ligação persistente, o cliente pode receber, intercalado, tanto a
 *   resposta a um comando que ele próprio enviou (RESP) como notificações
 *   assíncronas que chegam a qualquer momento (CHAT de outro utilizador,
 *   SYS de entrada/saída de canal). A etiqueta no início da linha permite
 *   ao cliente decidir imediatamente como tratar cada mensagem recebida,
 *   sem ambiguidade.
 *
 * PORQUÊ ESCAPAR '\n':
 *   O framing usa '\n' como delimitador de FIM DE MENSAGEM. Respostas como
 *   LIST_ALL ou VIEW_LOGS têm várias linhas de conteúdo. Para caberem numa
 *   única mensagem framed, os '\n' internos são substituídos por "\n"
 *   literal (backslash + n, 2 caracteres) antes de enviar. O cliente
 *   reverte essa substituição ao apresentar o conteúdo.
 *
 * Devolve 0 em sucesso, -1 em erro. */
int enviar_tagged(int fd, const char *tag, const char *conteudo);

/* Inverte o escape feito por enviar_tagged(): troca "\n" (2 caracteres)
 * de volta para um '\n' real, in-place, em 'texto'. */
void desescapar_newlines(char *texto);

/* Tenta extrair UMA linha completa (terminada em '\n') do buffer de
 * acumulação de um cliente. Se encontrar, copia para 'linha_out'
 * (sem o '\n'), remove-a do buffer (faz "deslizar" o resto), e devolve 1.
 * Se não houver linha completa ainda, devolve 0 sem alterar nada. */
int extrair_linha(cliente_t *cli, char *linha_out, size_t linha_out_size);

#endif /* PROTOCOLO_H */
