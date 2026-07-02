/*
 * ============================================================================
 * CRYPTO.H — Etapa 4: Criptografia (F11 + F12)
 * ============================================================================
 *
 * F11 — Cifra de César Generalizada:
 *   A cifra de César clássica só desloca letras (A-Z). A versão
 *   "generalizada" desloca TODO o intervalo de caracteres imprimíveis
 *   ASCII (32 a 126 — espaço, letras, dígitos, pontuação), não só letras.
 *
 *   PORQUÊ ficar dentro de 32-126 (e não usar todo o byte 0-255):
 *   O nosso protocolo usa '\n' (byte 10) como delimitador de fim de
 *   mensagem (ver protocolo.h). Se a cifra pudesse produzir QUALQUER byte,
 *   incluindo 0-31, arriscava-se a gerar um '\n' a meio do texto cifrado
 *   por acidente — e isso confundia o extrair_linha() do lado receptor,
 *   que pensaria que a mensagem tinha acabado ali. Ao restringir a cifra
 *   ao intervalo imprimível, garantimos matematicamente que nunca produz
 *   um '\n' (10) nem nenhum outro byte de controlo.
 *
 * F12 — Diffie-Hellman:
 *   Em vez de cliente e servidor usarem sempre a MESMA chave fixa (o que
 *   um atacante só precisaria de descobrir uma vez para ler todo o
 *   tráfego, de todas as sessões, para sempre), cada LIGAÇÃO negoceia a
 *   sua própria chave, através de um "aperto de mão" (handshake) onde
 *   apenas números públicos (A, B) viajam pela rede — nunca a chave em si.
 *   Mesmo que alguém intercete A e B, não consegue calcular a chave
 *   partilhada sem saber pelo menos um dos valores privados (a ou b),
 *   que nunca saem da máquina que os gerou.
 * ============================================================================
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "protocolo.h"

/* ---------------------------------------------------------------------
 * F11 — CIFRA DE CÉSAR GENERALIZADA
 * --------------------------------------------------------------------- */

/* Cifra/decifra 'texto' IN-PLACE (o próprio buffer é reescrito).
 * 'chave' é o deslocamento (normalmente vem de dh_derivar_chave_cesar). */
void cesar_cifrar_texto(char *texto, int chave);
void cesar_decifrar_texto(char *texto, int chave);

/* ---------------------------------------------------------------------
 * F12 — DIFFIE-HELLMAN
 * ---------------------------------------------------------------------
 *
 * DH_PRIMO (p) e DH_GERADOR (g) são PÚBLICOS por definição do algoritmo
 * — não há problema em estarem hardcoded e visíveis no código-fonte.
 * A segurança do DH não depende de p/g serem secretos, depende de ser
 * computacionalmente difícil inverter g^x mod p para descobrir x
 * (problema do logaritmo discreto).
 * --------------------------------------------------------------------- */
#define DH_PRIMO    2147483647LL   /* p: primo de Mersenne, 2^31 - 1 */
#define DH_GERADOR  5LL            /* g: gerador */

/* Exponenciação modular rápida: calcula (base^exp) mod m sem overflow,
 * usada tanto pelo DH como (mais tarde) pelo RSA toy (F13). */
long long modpow(long long base, long long exp, long long mod);

/* Gera um expoente privado aleatório (o 'a' ou 'b' de cada lado). */
long long dh_gerar_privada(void);

/* A = g^a mod p  (o valor que se ENVIA pela rede, em claro) */
long long dh_calcular_publica(long long privada);

/* S = B^a mod p  (o segredo PARTILHADO — nunca viaja pela rede) */
long long dh_calcular_partilhada(long long publica_remota, long long privada_propria);

/* Reduz o segredo partilhado (um número enorme) a uma chave de deslocamento
 * utilizável pela cifra de César (um valor pequeno, 1-94). */
int dh_derivar_chave_cesar(long long segredo_partilhado);

/* Handshake completo — trocam-se as chaves públicas e cada lado deriva a
 * MESMA chave simétrica de forma independente. Ver crypto.c para detalhe
 * de como isto se encaixa no framing (protocolo.h) sem quebrar o '\n'.
 * Devolvem 1 em sucesso, 0 em falha (liga a cli->chave_simetrica). */
int dh_handshake_servidor(cliente_t *cli);
int dh_handshake_cliente(cliente_t *sessao);

/* ---------------------------------------------------------------------
 * ENVIO CIFRADO (encaixa a cifra no framing existente)
 * --------------------------------------------------------------------- */

/* Cifra 'msg_plain' com César (chave) e só DEPOIS o envia framed (\n no
 * fim, sempre em claro) — ver protocolo.h para a explicação de porque a
 * ordem cifrar-depois-framar importa. */
int enviar_linha_cifrada(int fd, const char *msg_plain, int chave);

/* Equivalente cifrado de enviar_tagged() (protocolo.c): escapa \n,
 * prefixa a tag (RESP/SYS/CHAT), cifra tudo, e só depois enquadra. */
int enviar_tagged_cifrada(int fd, const char *tag, const char *conteudo, int chave);

/* ---------------------------------------------------------------------
 * F13 — SEGUNDA CIFRA SIMÉTRICA: XOR COM CHAVE REPETIDA
 * ---------------------------------------------------------------------
 *
 * Diferente da cifra de César (que desloca cada carácter), o XOR combina
 * cada byte do texto com um byte de uma chave que se repete ciclicamente:
 *   C[i] = M[i] XOR chave[i mod tamanho_da_chave]
 *
 * Propriedade importante do XOR: é a SUA PRÓPRIA operação inversa.
 * Cifrar duas vezes com a mesma chave devolve o texto original — por
 * isso esta única função serve para cifrar E para decifrar.
 *
 * Como o resultado pode conter QUALQUER byte (incluindo 0-31, ao
 * contrário da César), representa-se sempre em hexadecimal para
 * transmissão/apresentação — nunca se envia o ciphertext em bruto.
 * --------------------------------------------------------------------- */
#define XOR_CHAVE_OMISSAO ((const unsigned char *)"CCord2026Seguro")
#define XOR_CHAVE_OMISSAO_LEN 15

void xor_cifrar(unsigned char *dados, size_t len, const unsigned char *chave, size_t chave_len);

/* ---------------------------------------------------------------------
 * F13 — CIFRA ASSIMÉTRICA: RSA "TOY" (chaves pequenas, fins didáticos)
 * ---------------------------------------------------------------------
 *
 * Valores exactamente como no enunciado: par de chaves pequeno o
 * suficiente para calcular à mão/conferir manualmente.
 *   Chave pública  (e, n) = (17, 3233)   — usada para CIFRAR
 *   Chave privada  (d, n) = (2753, 3233) — usada para DECIFRAR
 *
 * Cada CARACTER é cifrado separadamente (não a mensagem toda de uma vez)
 * — daí precisar de modpow() por cada byte. Isto é o que torna o RSA
 * "toy" lento a sério (RSA real cifra blocos, não byte-a-byte) mas
 * suficiente para perceber o mecanismo matemático subjacente.
 * --------------------------------------------------------------------- */
#define RSA_E 17LL      /* expoente público */
#define RSA_D 2753LL    /* expoente privado */
#define RSA_N 3233LL    /* módulo (partilhado por e e d) */

long long rsa_cifrar_char(long long m);   /* C = M^e mod n */
long long rsa_decifrar_char(long long c); /* M = C^d mod n */

/* ---------------------------------------------------------------------
 * F13 — FUNÇÃO DE HASH (INTEGRIDADE)
 * ---------------------------------------------------------------------
 *
 * FNV-1a (Fowler-Noll-Vo): percorre a mensagem byte a byte, misturando
 * cada byte no acumulador com XOR + multiplicação por uma constante
 * prima. Não é criptograficamente forte (não serve para senhas!), mas
 * é uma forma simples e eficaz de detectar ALTERAÇÕES acidentais ou
 * maliciosas nos dados — qualquer mudança, por pequena que seja, tende
 * a mudar o hash completamente (efeito de avalanche).
 * --------------------------------------------------------------------- */
unsigned int hash_fnv1a(const char *texto);

/* ---------------------------------------------------------------------
 * UTILITÁRIOS DE REPRESENTAÇÃO (para bytes "crus" viajarem como texto)
 * --------------------------------------------------------------------- */
void bytes_para_hex(const unsigned char *dados, size_t len, char *hex_out);

#endif /* CRYPTO_H */
