/*
 * ============================================================================
 * CRYPTO.C — Implementação (ver crypto.h para a explicação de cada peça)
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"

/* ============================================================================
 * F11 — CIFRA DE CÉSAR GENERALIZADA
 * ============================================================================
 *
 * Só desloca caracteres imprimíveis (32-126). Qualquer outro byte passa
 * inalterado — na prática, o nosso protocolo é sempre texto, por isso
 * isto quase nunca acontece, mas protege contra bytes inesperados sem
 * partir a cifra nem produzir um '\n' por acidente (ver crypto.h).
 * ============================================================================
 */
static unsigned char cesar_cifrar_byte(unsigned char c, int chave) {
    if (c < 32 || c > 126) return c;      /* fora do alfabeto imprimivel */
    int pos = c - 32;                     /* posicao 0-94 dentro do alfabeto */
    pos = (pos + chave) % 95;
    if (pos < 0) pos += 95;
    return (unsigned char)(32 + pos);
}

static unsigned char cesar_decifrar_byte(unsigned char c, int chave) {
    if (c < 32 || c > 126) return c;
    int pos = c - 32;
    pos = (pos - chave) % 95;
    if (pos < 0) pos += 95;
    return (unsigned char)(32 + pos);
}

void cesar_cifrar_texto(char *texto, int chave) {
    for (size_t i = 0; texto[i] != '\0'; i++)
        texto[i] = (char)cesar_cifrar_byte((unsigned char)texto[i], chave);
}

void cesar_decifrar_texto(char *texto, int chave) {
    for (size_t i = 0; texto[i] != '\0'; i++)
        texto[i] = (char)cesar_decifrar_byte((unsigned char)texto[i], chave);
}

/* ============================================================================
 * F12 — DIFFIE-HELLMAN
 * ============================================================================
 */

/* Exponenciacao modular rapida (exponenciacao binaria / "square and
 * multiply"): calcula base^exp mod m em O(log exp) multiplicacoes, em vez
 * de multiplicar 'base' por si proprio 'exp' vezes (o que seria
 * impraticavel para exp grande, e faria overflow quase de certeza). */
long long modpow(long long base, long long exp, long long mod) {
    long long resultado = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1)
            resultado = (resultado * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return resultado;
}

/* Gera um expoente privado "aleatorio" (nao e criptograficamente seguro —
 * rand() nao serve para producao — mas e suficiente para o objectivo
 * academico de demonstrar o mecanismo do DH). Combina duas chamadas a
 * rand() para ter mais bits de entropia do que uma unica chamada
 * costuma oferecer. */
long long dh_gerar_privada(void) {
    static int seed_feito = 0;
    if (!seed_feito) {
        srand((unsigned int)(time(NULL) ^ getpid()));
        seed_feito = 1;
    }
    long long r = ((long long)rand() * 1000000007LL + (long long)rand())
                  % (DH_PRIMO - 4);
    if (r < 2) r += 2;
    return r;
}

long long dh_calcular_publica(long long privada) {
    return modpow(DH_GERADOR, privada, DH_PRIMO);
}

long long dh_calcular_partilhada(long long publica_remota, long long privada_propria) {
    return modpow(publica_remota, privada_propria, DH_PRIMO);
}

int dh_derivar_chave_cesar(long long segredo_partilhado) {
    int chave = (int)(segredo_partilhado % 95);
    if (chave == 0) chave = 1;   /* deslocamento 0 seria uma "cifra" que nao cifra nada */
    return chave;
}

/* ============================================================================
 * HANDSHAKE — troca das chaves publicas
 * ============================================================================
 *
 * Isto acontece UMA VEZ, logo a seguir ao accept()/connect(), ANTES de
 * qualquer outro comando (AUTH incluido). Como ainda nao ha chave
 * simetrica nesta fase, as duas linhas trocadas aqui ("DHPUB <numero>")
 * vao OBRIGATORIAMENTE em texto simples — nao ha problema nenhum nisso,
 * e a propria definicao do algoritmo: A e B sao valores PUBLICOS.
 *
 * SIMPLIFICACAO DELIBERADA: este handshake usa read()/enviar_linha()
 * directamente, em modo bloqueante, fora do ciclo select() principal.
 * Isto significa que, durante a fracção de segundo do handshake de UM
 * cliente a ligar-se, o servidor nao processa mais nada. Para um
 * handshake de 2 mensagens isto e imperceptivel na pratica, mas vale a
 * pena mencionar esta limitacao no relatorio como uma simplificacao
 * consciente face ao prazo, nao um descuido.
 * ============================================================================
 */

/* Função auxiliar partilhada pelos dois handshakes: lê a primeira linha
 * que chegar ao socket (bloqueante), extrai o número de "DHPUB <num>",
 * e guarda quaisquer bytes a mais que tenham vindo a seguir no buffer de
 * framing do cliente (para o select() principal os processar depois
 * normalmente — sem isto, poderíamos "engolir" o início do próximo
 * comando por engano). */
static int ler_dhpub(cliente_t *cli, long long *valor_out) {
    char temp[BUF_SIZE];
    int n = (int)read(cli->fd, temp, sizeof(temp) - 1);
    if (n <= 0) return 0;
    temp[n] = '\0';

    if (sscanf(temp, "DHPUB %lld", valor_out) != 1) return 0;

    char *fim_linha = memchr(temp, '\n', (size_t)n);
    if (fim_linha) {
        size_t resto = (size_t)n - (size_t)(fim_linha + 1 - temp);
        if (resto > 0 && resto < BUF_SIZE) {
            memcpy(cli->buffer_entrada, fim_linha + 1, resto);
            cli->buffer_len = resto;
        }
    }
    return 1;
}

int dh_handshake_servidor(cliente_t *cli) {
    long long priv = dh_gerar_privada();
    long long publica = dh_calcular_publica(priv);

    char msg[64];
    snprintf(msg, sizeof(msg), "DHPUB %lld", publica);
    if (enviar_linha(cli->fd, msg) != 0) return 0;

    long long publica_remota;
    if (!ler_dhpub(cli, &publica_remota)) return 0;

    long long partilhada = dh_calcular_partilhada(publica_remota, priv);
    cli->chave_simetrica = dh_derivar_chave_cesar(partilhada);
    return 1;
}

int dh_handshake_cliente(cliente_t *sessao) {
    /* O servidor envia o SEU valor público primeiro (assim que aceita a
     * ligação) — o cliente lê-o antes de enviar o dele, evitando que os
     * dois lados fiquem à espera um do outro (deadlock). */
    long long publica_remota;
    if (!ler_dhpub(sessao, &publica_remota)) return 0;

    long long priv = dh_gerar_privada();
    long long publica = dh_calcular_publica(priv);

    char msg[64];
    snprintf(msg, sizeof(msg), "DHPUB %lld", publica);
    if (enviar_linha(sessao->fd, msg) != 0) return 0;

    long long partilhada = dh_calcular_partilhada(publica_remota, priv);
    sessao->chave_simetrica = dh_derivar_chave_cesar(partilhada);
    return 1;
}

/* ============================================================================
 * ENVIO CIFRADO
 * ============================================================================
 */
int enviar_linha_cifrada(int fd, const char *msg_plain, int chave) {
    char buffer[LINHA_MAX];
    strncpy(buffer, msg_plain, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    cesar_cifrar_texto(buffer, chave);   /* cifra PRIMEIRO... */
    return enviar_linha(fd, buffer);     /* ...'\n' entra DEPOIS, sempre em claro */
}

int enviar_tagged_cifrada(int fd, const char *tag, const char *conteudo, int chave) {
    char escapado[LINHA_MAX];
    size_t j = 0;

    for (size_t i = 0; conteudo[i] != '\0' && j < sizeof(escapado) - 2; i++) {
        if (conteudo[i] == '\n') {
            escapado[j++] = '\\';
            escapado[j++] = 'n';
        } else if (conteudo[i] == '\r') {
            continue;
        } else {
            escapado[j++] = conteudo[i];
        }
    }
    escapado[j] = '\0';

    char framed[LINHA_MAX + 16];
    snprintf(framed, sizeof(framed), "%s:%s", tag, escapado);
    return enviar_linha_cifrada(fd, framed, chave);
}

/* ============================================================================
 * F13 — SEGUNDA CIFRA SIMÉTRICA: XOR
 * ============================================================================
 */
void xor_cifrar(unsigned char *dados, size_t len, const unsigned char *chave, size_t chave_len) {
    for (size_t i = 0; i < len; i++)
        dados[i] ^= chave[i % chave_len];
}

/* ============================================================================
 * F13 — RSA "TOY"
 * ============================================================================
 * Reutiliza modpow() (a mesma função do DH) — a exponenciação modular é
 * exactamente o mesmo problema matemático em ambos os algoritmos, só
 * muda o SIGNIFICADO dos números (aqui, chave pública/privada de RSA;
 * no DH, expoentes privados efémeros).
 */
long long rsa_cifrar_char(long long m) {
    return modpow(m, RSA_E, RSA_N);
}

long long rsa_decifrar_char(long long c) {
    return modpow(c, RSA_D, RSA_N);
}

/* ============================================================================
 * F13 — HASH FNV-1a (32 bits)
 * ============================================================================
 */
unsigned int hash_fnv1a(const char *texto) {
    unsigned int hash = 2166136261u;              /* offset basis (constante fixa do algoritmo) */
    for (size_t i = 0; texto[i] != '\0'; i++) {
        hash ^= (unsigned char)texto[i];
        hash *= 16777619u;                         /* FNV prime (constante fixa do algoritmo) */
    }
    return hash;
}

/* ============================================================================
 * UTILITÁRIO: bytes_para_hex()
 * ============================================================================
 */
void bytes_para_hex(const unsigned char *dados, size_t len, char *hex_out) {
    static const char digitos[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2]     = digitos[(dados[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = digitos[dados[i] & 0xF];
    }
    hex_out[len * 2] = '\0';
}
