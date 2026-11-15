/*
 * connect_scan.c — referencyjny TCP connect scan w C.
 *
 * Cel: dać punkt odniesienia do porównania z pynmap/scan_connect.py.
 * Ten sam algorytm, te same stałe, ta sama tabela errno -> stan portu,
 * ten sam estymator RTT (Jacobson/Karels) i to samo okno zatłoczenia.
 * Różni się tylko język.
 *
 * To NIE jest kod nmapa — jest napisany od zera na potrzeby porównania.
 * Oryginał (scan_engine_connect.cc) jest znacznie bardziej rozbudowany:
 * obsługuje wiele hostów, ping probes, IPv6, Windows, rate limiting
 * i integrację z NSE.
 *
 * Kompilacja:  make
 * Użycie:      ./connect_scan 127.0.0.1 1-1024
 *              ./connect_scan scanme.example.org 22,80,443 --reason
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Stałe — te same co w nmap.h i pynmap/constants.py                   */
/* ------------------------------------------------------------------ */

#define MIN_RTT_TIMEOUT_US      100000L     /* 100 ms  */
#define MAX_RTT_TIMEOUT_US    10000000L     /* 10 s    */
#define INITIAL_RTT_TIMEOUT_US 1000000L     /* 1 s     */
#define MAX_RETRANSMISSIONS         10

#define LOW_CWND                     1
#define MAX_CWND                   300
#define INITIAL_CWND                10
#define INITIAL_SSTHRESH            75
#define SLOW_INCR                    1
#define CA_INCR                      1
#define CC_SCALE_MAX                50
#define DROP_SSTHRESH_DIVISOR      1.5

#define MAX_PORTS                65535

/* ------------------------------------------------------------------ */
/* Stany portów i powody                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    PORT_UNKNOWN = 0,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED
} port_state_t;

typedef enum {
    ER_UNKNOWN = 0,
    ER_CONACCEPT,          /* connect() się udał — nmap drukuje "syn-ack" */
    ER_CONREFUSED,
    ER_ADMINPROHIBITED,
    ER_HOSTUNREACH,
    ER_NETUNREACH,
    ER_PROTOUNREACH,
    ER_DESTUNREACH,
    ER_NORESPONSE
} reason_t;

static const char *state_str(port_state_t s)
{
    switch (s) {
    case PORT_OPEN:     return "open";
    case PORT_CLOSED:   return "closed";
    case PORT_FILTERED: return "filtered";
    default:            return "unknown";
    }
}

static const char *reason_str(reason_t r)
{
    switch (r) {
    case ER_CONACCEPT:       return "syn-ack";
    case ER_CONREFUSED:      return "conn-refused";
    case ER_ADMINPROHIBITED: return "admin-prohibited";
    case ER_HOSTUNREACH:     return "host-unreach";
    case ER_NETUNREACH:      return "net-unreach";
    case ER_PROTOUNREACH:    return "proto-unreach";
    case ER_DESTUNREACH:     return "dest-unreach";
    case ER_NORESPONSE:      return "no-response";
    default:                 return "unknown";
    }
}

/*
 * Tabela errno -> (stan, powód). Przepisana z handleConnectResult()
 * w nmap/scan_engine_connect.cc. W Pythonie to jeden słownik; tutaj
 * musi być funkcja ze switchem, bo C nie ma literałów map.
 */
static void classify_errno(int code, port_state_t *state, reason_t *reason)
{
    switch (code) {
    case 0:
    case EISCONN:
        *state = PORT_OPEN;      *reason = ER_CONACCEPT;       break;
    case EAGAIN:                 /* quirk pętli lokalnej w Linuksie */
        *state = PORT_OPEN;      *reason = ER_CONACCEPT;       break;
    case ECONNREFUSED:
        *state = PORT_CLOSED;    *reason = ER_CONREFUSED;      break;
    case EACCES:
    case EPERM:
        *state = PORT_FILTERED;  *reason = ER_ADMINPROHIBITED; break;
    case ENOPROTOOPT:
        *state = PORT_FILTERED;  *reason = ER_PROTOUNREACH;    break;
    case EHOSTUNREACH:
        *state = PORT_FILTERED;  *reason = ER_HOSTUNREACH;     break;
    case ENETUNREACH:
        *state = PORT_FILTERED;  *reason = ER_NETUNREACH;      break;
#ifdef ENONET
    case ENONET:
        *state = PORT_FILTERED;  *reason = ER_DESTUNREACH;     break;
#endif
    case ETIMEDOUT:
    case EHOSTDOWN:
        *state = PORT_FILTERED;  *reason = ER_NORESPONSE;      break;
    default:
        *state = PORT_UNKNOWN;   *reason = ER_UNKNOWN;         break;
    }
}

/* ------------------------------------------------------------------ */
/* Estymator RTT — odpowiednik adjust_timeouts2()                      */
/* ------------------------------------------------------------------ */

struct timeout_info {
    long srtt;      /* wygładzony RTT [µs], -1 = brak próbki */
    long rttvar;    /* wariancja [µs]                        */
    long timeout;   /* aktualny próg [µs]                    */
};

static void timeout_init(struct timeout_info *to)
{
    to->srtt = -1;
    to->rttvar = -1;
    to->timeout = INITIAL_RTT_TIMEOUT_US;
}

static long box_l(long low, long high, long value)
{
    if (value < low)  return low;
    if (value > high) return high;
    return value;
}

static void timeout_adjust(struct timeout_info *to, long delta)
{
    if (delta < 0 && delta > -50000)
        delta = 10000;              /* rozjazd zegarów */
    else if (delta < 0)
        return;

    if (to->srtt == -1 && to->rttvar == -1) {
        to->srtt = delta;
        to->rttvar = box_l(5000, 2000000, to->srtt);
        to->timeout = to->srtt + (to->rttvar << 2);
    } else {
        long rttdelta;

        if (delta >= 8000000)
            return;

        rttdelta = delta - to->srtt;
        if (rttdelta > 1500000 && rttdelta > 3 * to->srtt + 2 * to->rttvar)
            return;

        to->srtt   += rttdelta >> 3;
        to->rttvar += (labs(rttdelta) - to->rttvar) >> 2;
        to->timeout = to->srtt + (to->rttvar << 2);
    }

    if (to->rttvar > 2300000)
        to->rttvar = 2000000;

    to->timeout = box_l(MIN_RTT_TIMEOUT_US, MAX_RTT_TIMEOUT_US, to->timeout);
}

/* ------------------------------------------------------------------ */
/* Okno zatłoczenia — odpowiednik ultra_timing_vals                    */
/* ------------------------------------------------------------------ */

struct timing_vals {
    double cwnd;
    int    ssthresh;
    long   replies_expected;
    long   replies_received;
};

static void timing_init(struct timing_vals *t)
{
    t->cwnd = INITIAL_CWND;
    t->ssthresh = INITIAL_SSTHRESH;
    t->replies_expected = 0;
    t->replies_received = 0;
}

static double cc_scale(const struct timing_vals *t)
{
    double ratio;

    if (t->replies_received <= 0)
        return 1.0;

    ratio = (double)t->replies_expected / (double)t->replies_received;
    return ratio < CC_SCALE_MAX ? ratio : CC_SCALE_MAX;
}

static void timing_ack(struct timing_vals *t)
{
    double scale;

    t->replies_received++;
    scale = cc_scale(t);

    if (t->cwnd < t->ssthresh) {
        t->cwnd += SLOW_INCR * scale;
        if (t->cwnd > t->ssthresh)
            t->cwnd = t->ssthresh;
    } else {
        t->cwnd += CA_INCR / t->cwnd * scale;
    }

    if (t->cwnd > MAX_CWND)
        t->cwnd = MAX_CWND;
}

static void timing_drop(struct timing_vals *t, int in_flight)
{
    int new_ssthresh;

    t->cwnd = LOW_CWND;
    new_ssthresh = (int)(in_flight / DROP_SSTHRESH_DIVISOR);
    t->ssthresh = new_ssthresh > 2 ? new_ssthresh : 2;
}

/* ------------------------------------------------------------------ */
/* Sonda i wynik                                                       */
/* ------------------------------------------------------------------ */

struct probe {
    int            fd;
    int            port;
    int            tryno;
    struct timeval sent_at;
    struct timeval expires_at;
    bool           active;
};

struct port_result {
    int          port;
    port_state_t state;
    reason_t     reason;
    long         rtt_us;
};

/* ------------------------------------------------------------------ */
/* Narzędzia czasowe                                                   */
/* ------------------------------------------------------------------ */

static long tv_diff_us(const struct timeval *a, const struct timeval *b)
{
    return (a->tv_sec - b->tv_sec) * 1000000L + (a->tv_usec - b->tv_usec);
}

static void tv_add_us(struct timeval *tv, long usec)
{
    tv->tv_sec  += usec / 1000000L;
    tv->tv_usec += usec % 1000000L;
    if (tv->tv_usec >= 1000000L) {
        tv->tv_sec++;
        tv->tv_usec -= 1000000L;
    }
}

/* ------------------------------------------------------------------ */
/* Parsowanie portów — odpowiednik getpts()                            */
/* ------------------------------------------------------------------ */

/* Mapa bitowa "port juz dodany" — 8 KB, wiec spokojnie na stosie.
 * Wersja w Pythonie trzyma porty w set(), wiec '22,22,80' daje tam DWA porty.
 * Tutaj kazde wystapienie dopisywalo osobny wpis, a record_result()
 * aktualizuje tylko PIERWSZY wpis o danym numerze i wraca — duplikaty
 * zostawaly ze stanem domyslnym (filtered/no-response). Raport pokazywal
 * wiec ten sam port dwa razy, w dwoch sprzecznych stanach, a podsumowanie
 * liczylo porty, ktorych nie ma. */
#define SEEN_BYTES ((MAX_PORTS + 8) / 8)

static bool seen_add(unsigned char *seen, int port)
{
    const int idx = port >> 3;
    const unsigned char bit = (unsigned char)(1u << (port & 7));

    if (seen[idx] & bit)
        return false;
    seen[idx] |= bit;
    return true;
}

/* Ile razy pod rzad tolerujemy porazke socket() przy zerowej liczbie sond
 * w locie, zanim uznamy skan za niewykonalny. Tyle samo co w wersji
 * w Pythonie (_FD_FAILURE_LIMIT w pynmap/scan_connect.py). */
#define FD_FAILURE_LIMIT 3

static int parse_ports(const char *spec, int *ports, int max_ports)
{
    char *copy, *token, *saveptr;
    int count = 0;
    unsigned char seen[SEEN_BYTES];

    memset(seen, 0, sizeof(seen));

    copy = strdup(spec);
    if (copy == NULL) {
        perror("strdup");
        return -1;
    }

    if (strcmp(spec, "-") == 0) {
        free(copy);
        for (int p = 1; p <= MAX_PORTS && count < max_ports; p++)
            ports[count++] = p;
        return count;
    }

    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL) {
        char *dash = strchr(token, '-');

        if (dash != NULL) {
            int lo, hi;

            *dash = '\0';
            lo = (*token == '\0') ? 1 : atoi(token);
            hi = (*(dash + 1) == '\0') ? MAX_PORTS : atoi(dash + 1);

            if (lo < 1 || hi > MAX_PORTS || lo > hi) {
                fprintf(stderr, "Niepoprawny zakres portów: %s-%s\n",
                        token, dash + 1);
                free(copy);
                return -1;
            }
            for (int p = lo; p <= hi && count < max_ports; p++)
                if (seen_add(seen, p))
                    ports[count++] = p;
        } else {
            int p = atoi(token);

            if (p < 1 || p > MAX_PORTS) {
                fprintf(stderr, "Port poza zakresem 1-65535: %s\n", token);
                free(copy);
                return -1;
            }
            if (count < max_ports && seen_add(seen, p))
                ports[count++] = p;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    return count;
}

/* Komparator do qsort() przy wypisywaniu raportu rosnąco po porcie */
static int compare_results_by_port(const void *a, const void *b)
{
    const struct port_result *ra = a;
    const struct port_result *rb = b;

    if (ra->port < rb->port) return -1;
    if (ra->port > rb->port) return 1;
    return 0;
}

/* Tasowanie Fishera-Yatesa — odpowiednik losowania kolejności portów */
static void shuffle_ports(int *ports, int count)
{
    for (int i = count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = ports[i];
        ports[i] = ports[j];
        ports[j] = tmp;
    }
}

/* ------------------------------------------------------------------ */
/* Limit deskryptorów                                                  */
/* ------------------------------------------------------------------ */

static int max_sockets_allowed(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return 1024;
    if (rl.rlim_cur == RLIM_INFINITY)
        return 1024;
    if (rl.rlim_cur < 40)
        return 8;

    return (int)(rl.rlim_cur - 32) > 1024 ? 1024 : (int)(rl.rlim_cur - 32);
}

/* ------------------------------------------------------------------ */
/* Główna pętla skanowania                                             */
/* ------------------------------------------------------------------ */

struct scanner {
    struct sockaddr_storage target;
    socklen_t               target_len;
    int                     family;

    int                *ports;
    int                 port_count;
    int                 next_port_idx;

    int                *retry_stack;
    int                 retry_count;
    bool                aborted;
    int                *tryno;          /* indeksowane numerem portu */

    struct probe       *probes;
    int                 probe_capacity;
    int                 in_flight;
    /* Ile razy pod rzad socket() zawiodl, nie majac ani jednej sondy w locie.
     * Bez takiego licznika nie ma kto zwolnic deskryptora: port wracal na
     * retry_stack bez podniesienia tryno, launch_probe() zwracal false,
     * wait_for_responses() mialo maxfd < 0 i tylko spalo 1 ms, work_left()
     * bylo nadal prawdziwe — i petla glowna krecila sie bez konca, nie
     * wypisujac nic i nie konczac sie. Wersja w Pythonie wychodzi w tej
     * sytuacji z czytelnym komunikatem (patrz docs/c-vs-python.md). */
    int                 fd_failures;

    struct port_result *results;

    struct timeout_info to;
    struct timing_vals  timing;

    int                 max_retries;
    long                probes_sent;
    long                replies;
};

static void set_target_port(struct scanner *sc, int port)
{
    if (sc->family == AF_INET6)
        ((struct sockaddr_in6 *)&sc->target)->sin6_port = htons((uint16_t)port);
    else
        ((struct sockaddr_in *)&sc->target)->sin_port = htons((uint16_t)port);
}

static int next_port(struct scanner *sc)
{
    if (sc->retry_count > 0)
        return sc->retry_stack[--sc->retry_count];
    if (sc->next_port_idx < sc->port_count)
        return sc->ports[sc->next_port_idx++];
    return -1;
}

static struct probe *free_probe_slot(struct scanner *sc)
{
    for (int i = 0; i < sc->probe_capacity; i++)
        if (!sc->probes[i].active)
            return &sc->probes[i];
    return NULL;
}

static void record_result(struct scanner *sc, int port, port_state_t state,
                          reason_t reason, long rtt_us)
{
    for (int i = 0; i < sc->port_count; i++) {
        if (sc->results[i].port == port) {
            sc->results[i].state  = state;
            sc->results[i].reason = reason;
            sc->results[i].rtt_us = rtt_us;
            return;
        }
    }
}

static void close_probe(struct scanner *sc, struct probe *p)
{
    if (p->fd >= 0)
        close(p->fd);
    p->fd = -1;
    p->active = false;
    sc->in_flight--;
}

/*
 * Wysyła jedną sondę: tworzy nieblokujący socket i woła connect().
 * Odpowiednik _launch_probe() w Pythonie.
 */
static bool launch_probe(struct scanner *sc, int port, const struct timeval *now)
{
    struct probe *p;
    int fd, flags, rc;
    struct linger lg = { 1, 0 };

    p = free_probe_slot(sc);
    if (p == NULL)
        return false;

    fd = socket(sc->family, SOCK_STREAM, 0);
    if (fd < 0) {
        if (errno == EMFILE || errno == ENFILE) {
            /* brak deskryptorów — port wraca do kolejki */
            sc->retry_stack[sc->retry_count++] = port;
            if (sc->in_flight > 0) {
                /* cos leci i zwolni deskryptor — warto poczekac */
                return false;
            }
            if (++sc->fd_failures >= FD_FAILURE_LIMIT) {
                fprintf(stderr,
                        "connect_scan: brak wolnych deskryptorow (%s) — "
                        "zwieksz ulimit -n\n", strerror(errno));
                sc->aborted = true;
            }
            return false;
        }
        perror("socket");
        return false;
    }

    sc->fd_failures = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl");
        close(fd);
        return false;
    }

    /* RST zamiast FIN przy zamknięciu — jak init_socket() w nmapie */
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    set_target_port(sc, port);

    p->fd         = fd;
    p->port       = port;
    p->tryno      = sc->tryno[port];
    p->sent_at    = *now;
    p->expires_at = *now;
    p->active     = true;
    tv_add_us(&p->expires_at, sc->to.timeout);

    sc->in_flight++;
    sc->probes_sent++;
    sc->timing.replies_expected++;

    rc = connect(fd, (struct sockaddr *)&sc->target, sc->target_len);

    if (rc == 0) {
        /* natychmiastowy sukces (typowe dla localhost) */
        record_result(sc, port, PORT_OPEN, ER_CONACCEPT, 0);
        sc->replies++;
        close_probe(sc, p);
        return true;
    }

    if (errno != EINPROGRESS && errno != EALREADY) {
        port_state_t state;
        reason_t reason;

        classify_errno(errno, &state, &reason);
        if (state == PORT_UNKNOWN) {
            state = PORT_FILTERED;
            reason = ER_NORESPONSE;
        }
        record_result(sc, port, state, reason, 0);
        sc->replies++;
        close_probe(sc, p);
        return true;
    }

    /* EINPROGRESS: czekamy w select() */
    return true;
}

/* Odpowiednik doAnyOutstandingRetransmits() */
static void handle_timeouts(struct scanner *sc, const struct timeval *now)
{
    for (int i = 0; i < sc->probe_capacity; i++) {
        struct probe *p = &sc->probes[i];

        if (!p->active)
            continue;
        if (tv_diff_us(now, &p->expires_at) < 0)
            continue;

        timing_drop(&sc->timing, sc->in_flight);

        if (p->tryno < sc->max_retries) {
            sc->tryno[p->port] = p->tryno + 1;
            sc->retry_stack[sc->retry_count++] = p->port;
        } else {
            record_result(sc, p->port, PORT_FILTERED, ER_NORESPONSE, 0);
        }
        close_probe(sc, p);
    }
}

/* Odpowiednik do_one_select_round() */
static void wait_for_responses(struct scanner *sc)
{
    fd_set wfds;
    struct timeval tv, now, soonest;
    int maxfd = -1;
    bool have_soonest = false;
    int ready;

    FD_ZERO(&wfds);

    for (int i = 0; i < sc->probe_capacity; i++) {
        struct probe *p = &sc->probes[i];

        if (!p->active || p->fd < 0)
            continue;

        FD_SET(p->fd, &wfds);
        if (p->fd > maxfd)
            maxfd = p->fd;

        if (!have_soonest || tv_diff_us(&p->expires_at, &soonest) < 0) {
            soonest = p->expires_at;
            have_soonest = true;
        }
    }

    if (maxfd < 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        select(0, NULL, NULL, NULL, &tv);
        return;
    }

    gettimeofday(&now, NULL);
    {
        long wait_us = have_soonest ? tv_diff_us(&soonest, &now) : 100000L;

        if (wait_us < 0)
            wait_us = 0;
        if (wait_us > 100000L)
            wait_us = 100000L;       /* nie śpimy dłużej niż 100 ms */

        tv.tv_sec  = wait_us / 1000000L;
        tv.tv_usec = wait_us % 1000000L;
    }

    ready = select(maxfd + 1, NULL, &wfds, NULL, &tv);
    if (ready <= 0)
        return;

    gettimeofday(&now, NULL);

    for (int i = 0; i < sc->probe_capacity; i++) {
        struct probe *p = &sc->probes[i];
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        port_state_t state;
        reason_t reason;
        long rtt;

        if (!p->active || p->fd < 0 || !FD_ISSET(p->fd, &wfds))
            continue;

        if (getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0)
            so_error = ETIMEDOUT;

        classify_errno(so_error, &state, &reason);
        if (state == PORT_UNKNOWN) {
            state = PORT_FILTERED;
            reason = ER_NORESPONSE;
        }

        rtt = tv_diff_us(&now, &p->sent_at);

        /* nmap nie uczy się RTT z retransmisji */
        if (p->tryno == 0)
            timeout_adjust(&sc->to, rtt);

        timing_ack(&sc->timing);
        record_result(sc, p->port, state, reason, rtt);
        sc->replies++;
        close_probe(sc, p);
    }
}

static bool work_left(const struct scanner *sc)
{
    if (sc->aborted)
        return false;   /* nie ma jak zrobic postepu — patrz fd_failures */

    return sc->next_port_idx < sc->port_count ||
           sc->retry_count > 0 ||
           sc->in_flight > 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Użycie: %s <host> <porty> [--reason] [--open] [-r]\n"
            "  porty:    80 | 1-1024 | 22,80,443 | -\n"
            "  --reason: pokaż powód przypisania stanu\n"
            "  --open:   pokaż tylko porty otwarte\n"
            "  -r:       nie losuj kolejności portów\n",
            prog);
}

int main(int argc, char **argv)
{
    struct scanner sc;
    struct addrinfo hints, *res;
    struct timeval start, end, now;
    bool show_reason = false, only_open = false, randomize = true;
    int rc, max_sockets;
    const char *host, *portspec;
    char addrbuf[INET6_ADDRSTRLEN] = "?";

    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }

    host = argv[1];
    portspec = argv[2];

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--reason") == 0)      show_reason = true;
        else if (strcmp(argv[i], "--open") == 0)   only_open = true;
        else if (strcmp(argv[i], "-r") == 0)       randomize = false;
        else {
            fprintf(stderr, "Nieznana opcja: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    memset(&sc, 0, sizeof(sc));

    /* --- rozwiązanie nazwy -------------------------------------- */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "Nie udało się rozwiązać '%s': %s\n",
                host, gai_strerror(rc));
        return 1;
    }

    memcpy(&sc.target, res->ai_addr, res->ai_addrlen);
    sc.target_len = res->ai_addrlen;
    sc.family = res->ai_family;

    if (sc.family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sc.target)->sin6_addr,
                  addrbuf, sizeof(addrbuf));
    else
        inet_ntop(AF_INET, &((struct sockaddr_in *)&sc.target)->sin_addr,
                  addrbuf, sizeof(addrbuf));

    freeaddrinfo(res);

    /* --- porty --------------------------------------------------- */
    sc.ports = calloc(MAX_PORTS, sizeof(int));
    sc.retry_stack = calloc(MAX_PORTS, sizeof(int));
    sc.tryno = calloc(MAX_PORTS + 1, sizeof(int));
    if (sc.ports == NULL || sc.retry_stack == NULL || sc.tryno == NULL) {
        perror("calloc");
        free(sc.ports); free(sc.retry_stack); free(sc.tryno);
        return 1;
    }

    sc.port_count = parse_ports(portspec, sc.ports, MAX_PORTS);
    if (sc.port_count <= 0) {
        free(sc.ports); free(sc.retry_stack); free(sc.tryno);
        return 2;
    }

    sc.results = calloc((size_t)sc.port_count, sizeof(struct port_result));
    if (sc.results == NULL) {
        perror("calloc");
        free(sc.ports); free(sc.retry_stack); free(sc.tryno);
        return 1;
    }
    for (int i = 0; i < sc.port_count; i++) {
        sc.results[i].port   = sc.ports[i];
        sc.results[i].state  = PORT_FILTERED;   /* stan domyślny */
        sc.results[i].reason = ER_NORESPONSE;
        sc.results[i].rtt_us = -1;
    }

    srand((unsigned)time(NULL));
    if (randomize)
        shuffle_ports(sc.ports, sc.port_count);

    /* --- stan silnika -------------------------------------------- */
    max_sockets = max_sockets_allowed();
    sc.probe_capacity = max_sockets < sc.port_count ? max_sockets : sc.port_count;
    sc.probes = calloc((size_t)sc.probe_capacity, sizeof(struct probe));
    if (sc.probes == NULL) {
        perror("calloc");
        free(sc.ports); free(sc.retry_stack); free(sc.tryno); free(sc.results);
        return 1;
    }
    for (int i = 0; i < sc.probe_capacity; i++)
        sc.probes[i].fd = -1;

    timeout_init(&sc.to);
    timing_init(&sc.timing);
    sc.max_retries = MAX_RETRANSMISSIONS;

    printf("Starting connect_scan (C reference) against %s [%d portów]\n",
           addrbuf, sc.port_count);

    gettimeofday(&start, NULL);

    /* --- pętla główna: ta sama kolejność faz co w Pythonie ------- */
    while (work_left(&sc)) {
        gettimeofday(&now, NULL);

        handle_timeouts(&sc, &now);

        /* wysyłaj, dopóki pozwala okno zatłoczenia i limit deskryptorów */
        while (sc.in_flight < (int)sc.timing.cwnd &&
               sc.in_flight < sc.probe_capacity) {
            int port = next_port(&sc);

            if (port < 0)
                break;
            gettimeofday(&now, NULL);
            if (!launch_probe(&sc, port, &now))
                break;
        }

        wait_for_responses(&sc);
    }

    gettimeofday(&end, NULL);

    /* --- raport --------------------------------------------------- */
    {
        int open_count = 0, closed_count = 0, filtered_count = 0;
        char label[16];

        /*
         * Sortujemy wyniki po numerze portu i wypisujemy liniowo: O(n log n).
         * Pierwsza wersja robiła tu podwójną pętlę po 1..65535 i po tablicy
         * wyników, czyli O(65535 * n) — przy 1024 portach to 67 mln iteracji
         * i raport trwał dłużej niż sam skan.
         */
        qsort(sc.results, (size_t)sc.port_count,
              sizeof(struct port_result), compare_results_by_port);

        printf("\n%-10s%-12s%s\n", "PORT", "STATE",
               show_reason ? "REASON" : "");

        for (int i = 0; i < sc.port_count; i++) {
            switch (sc.results[i].state) {
            case PORT_OPEN:     open_count++;     break;
            case PORT_CLOSED:   closed_count++;   break;
            default:            filtered_count++; break;
            }

            if (only_open && sc.results[i].state != PORT_OPEN)
                continue;

            snprintf(label, sizeof(label), "%d/tcp", sc.results[i].port);
            printf("%-10s%-12s", label, state_str(sc.results[i].state));
            if (show_reason)
                printf("%s", reason_str(sc.results[i].reason));
            printf("\n");
        }

        printf("\nPodsumowanie: %d open, %d closed, %d filtered\n",
               open_count, closed_count, filtered_count);
        printf("Sondy wysłane: %ld, odpowiedzi: %ld\n", sc.probes_sent, sc.replies);
        printf("Czas: %.3f s (srtt=%ld µs, timeout=%ld µs, cwnd=%.1f)\n",
               tv_diff_us(&end, &start) / 1000000.0,
               sc.to.srtt, sc.to.timeout, sc.timing.cwnd);
    }

    /* --- sprzątanie: w Pythonie zrobiłby to GC ------------------- */
    for (int i = 0; i < sc.probe_capacity; i++)
        if (sc.probes[i].fd >= 0)
            close(sc.probes[i].fd);

    free(sc.probes);
    free(sc.results);
    free(sc.tryno);
    free(sc.retry_stack);
    free(sc.ports);

    return 0;
}
