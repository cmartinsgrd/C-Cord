/*
 * ============================================================================
 * PROTOCOLO.C — Implementação do framing de mensagens (ver protocolo.h)
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>

#include "protocolo.h"

#ifdef _WIN32
    #include <winsock2.h>
    #define WRITE_SOCKET(s, buf, len) send(s, buf, (int)(len), 0)
#else
    #include <unistd.h>
    #define WRITE_SOCKET(s, buf, len) write(s, buf, len)
#endif

/* ============================================================================
 * FUNÇÃO: enviar_linha()
 * ============================================================================
 *
 * Garante que toda a mensagem enviada termina em '\n', que é o delimitador
 * que o lado receptor usa para saber "aqui acaba uma mensagem".
 *
 * Porquê não usar simplesmente strcat(msg, "\n") no chamador?
 *   Para não obrigar TODO o código que envia mensagens a lembrar-se de
 *   acrescentar o delimitador — centraliza a regra num único sítio.
 * ============================================================================
 */
int enviar_linha(int fd, const char *msg) {
    char framed[LINHA_MAX + 2];
    size_t len = strlen(msg);

    if (len > LINHA_MAX) len = LINHA_MAX;   /* protecção contra overflow */

    memcpy(framed, msg, len);
    framed[len]     = '\n';
    framed[len + 1] = '\0';

    if (WRITE_SOCKET(fd, framed, len + 1) < 0) return -1;
    return 0;
}

/* ============================================================================
 * FUNÇÃO: extrair_linha()
 * ============================================================================
 *
 * Procura um '\n' dentro de cli->buffer_entrada (que contém tudo o que já
 * foi lido do socket mas ainda não foi processado).
 *
 * Caso encontre:
 *   1. Copia os bytes ANTES do '\n' para linha_out (a mensagem completa)
 *   2. "Desliza" o que sobra no buffer (o que veio DEPOIS do '\n', que pode
 *      ser o início da próxima mensagem ou nada) para o início
 *   3. Actualiza buffer_len para refletir o que sobrou
 *   4. Devolve 1
 *
 * Caso não encontre '\n':
 *   Não há mensagem completa ainda — pode ter chegado só metade pela rede.
 *   Devolve 0 e não mexe em nada (os dados continuam à espera do próximo
 *   recv() que vai ACRESCENTAR mais bytes ao fim do buffer).
 *
 * Nota importante: esta função NÃO faz recv(). Só opera sobre dados que
 * já estão em memória. Quem chama esta função é responsável por, antes,
 * ter feito recv() e ACRESCENTADO os bytes novos ao fim de buffer_entrada.
 * ============================================================================
 */
int extrair_linha(cliente_t *cli, char *linha_out, size_t linha_out_size) {
    char *pos = memchr(cli->buffer_entrada, '\n', cli->buffer_len);
    if (!pos) return 0;   /* ainda não chegou uma mensagem completa */

    size_t tam_linha = (size_t)(pos - cli->buffer_entrada);

    if (tam_linha >= linha_out_size) tam_linha = linha_out_size - 1;
    memcpy(linha_out, cli->buffer_entrada, tam_linha);
    linha_out[tam_linha] = '\0';

    /* Remove \r final, se existir (clientes Windows/telnet podem enviar \r\n) */
    if (tam_linha > 0 && linha_out[tam_linha - 1] == '\r')
        linha_out[tam_linha - 1] = '\0';

    /* Deslizar o resto do buffer para o início */
    size_t resto_inicio = (size_t)(pos - cli->buffer_entrada) + 1; /* a seguir ao \n */
    size_t resto_tam     = cli->buffer_len - resto_inicio;

    memmove(cli->buffer_entrada, cli->buffer_entrada + resto_inicio, resto_tam);
    cli->buffer_len = resto_tam;

    return 1;
}

/* ============================================================================
 * FUNÇÃO: enviar_tagged()
 * Ver explicação detalhada em protocolo.h.
 * ============================================================================
 */
int enviar_tagged(int fd, const char *tag, const char *conteudo) {
    char escapado[LINHA_MAX];
    size_t j = 0;

    for (size_t i = 0; conteudo[i] != '\0' && j < sizeof(escapado) - 2; i++) {
        if (conteudo[i] == '\n') {
            escapado[j++] = '\\';
            escapado[j++] = 'n';
        } else if (conteudo[i] == '\r') {
            continue; /* descarta \r, mantemos so \n como quebra logica */
        } else {
            escapado[j++] = conteudo[i];
        }
    }
    escapado[j] = '\0';

    char framed[LINHA_MAX + 16];
    snprintf(framed, sizeof(framed), "%s:%s", tag, escapado);
    return enviar_linha(fd, framed);
}

/* ============================================================================
 * FUNÇÃO: desescapar_newlines()
 * Ver explicação detalhada em protocolo.h.
 * ============================================================================
 */
void desescapar_newlines(char *texto) {
    char *leitura = texto, *escrita = texto;
    while (*leitura) {
        if (leitura[0] == '\\' && leitura[1] == 'n') {
            *escrita++ = '\n';
            leitura += 2;
        } else {
            *escrita++ = *leitura++;
        }
    }
    *escrita = '\0';
}

