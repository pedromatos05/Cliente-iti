#!/usr/bin/env python3
"""
pdfer_client.py - Cliente para o servidor PDFer (ITI 2025/2026).

O servidor PDFer tem três métodos:
  GET  /files            lista os ficheiros da pasta "store"           (sem parâmetros)
  POST /files            cria e cifra um ficheiro          (body: key, length, fileName)
  GET  /files/{fileId}   decifra e devolve um ficheiro                       (body: key)

O cliente tem duas partes:

1) PEDIDOS NORMAIS (como o curl) - mostram a resposta do servidor
     list                      lista os nomes dos ficheiros
     get  <fileId>             mostra o conteúdo decifrado de um ficheiro
     post <fileName> -l N      cria um ficheiro com N caracteres
     post -c 50 -t 4 -l N      cria 50 ficheiros, 4 em simultâneo (threads)

2) TESTES DE PRESSÃO - muitos pedidos com threads; mostram métricas
     stress --mode post|get|list|mixed
   Resumo no ecrã (débito, média, p50, p95, p99), CSV com uma linha por pedido
   e, com --metrics-port, métricas para o Prometheus/Grafana.
   Os GET nunca criam ficheiros: leem ficheiros que já existem no servidor.

A chave (key) tem de ter exatamente 16 bytes; por omissão é "chave-de-teste16".
Usa apenas a biblioteca padrão do Python 3 (não é preciso instalar nada).

Exemplos:
  python3 pdfer_client.py list
  python3 pdfer_client.py post teste1.txt --length 1000
  python3 pdfer_client.py get teste1.txt
  python3 pdfer_client.py post --count 20 --threads 4 --length 10000 --prefix e1-
  python3 pdfer_client.py stress --mode get --prefix e1- --threads 4 --requests 200
  python3 pdfer_client.py stress --mode post --length 1000 --threads 2 --duration 60
  python3 pdfer_client.py stress --mode mixed --post-ratio 0.3 --list-ratio 0.1 \\
          --threads 4 --duration 120 --metrics-port 9200
"""

import argparse
import csv
import http.client
import json
import os
import random
import socket
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "192.168.57.11"
DEFAULT_PORT = 8080
DEFAULT_KEY = "chave-de-teste16"
KEY_BYTES = 16          # o PDFer só aceita chaves de 16 bytes

SERVER_FIELDS = [
    "total",
    "readFileSystemEntries",
    "generateFile",
    "encryption",
    "writeFile",
    "readFile",
    "decryption",
]

FIELD_LABELS = {          # nomes curtos para mostrar no ecrã
    "total": "total",
    "readFileSystemEntries": "ler a pasta",
    "generateFile": "gerar",
    "encryption": "cifrar",
    "writeFile": "escrever",
    "readFile": "ler",
    "decryption": "decifrar",
}

CSV_COLUMNS = [
    "run_id", "seq", "worker", "phase", "method", "length", "file_name", "files_listed",
    "start_epoch", "client_ms", "http_status", "ok", "error", "response_bytes",
] + [f"srv_{f}_us" for f in SERVER_FIELDS]


# ==========================================================================
# Comunicação com o servidor
# ==========================================================================
class PdferConnection:
    """Uma ligação HTTP persistente (keep-alive). Usar uma por thread."""

    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.conn = None

    def _connect(self):
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        self.conn.connect()
        # Desliga o algoritmo de Nagle: evita atrasos artificiais (~40 ms)
        # em pedidos pequenos, que falseariam os tempos medidos.
        self.conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def request(self, method, path, payload):
        """Envia o pedido e devolve (status, corpo da resposta, tempo em ms)."""
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        for attempt in (1, 2):  # 2.ª tentativa só se a ligação keep-alive tiver caído
            if self.conn is None:
                self._connect()
            try:
                t0 = time.perf_counter()
                self.conn.request(method, path, body=body, headers=headers)
                resp = self.conn.getresponse()
                data = resp.read()
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return resp.status, data, elapsed_ms
            except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
                self.close()
                if attempt == 2:
                    raise

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            finally:
                self.conn = None


# Os três métodos do PDFer, com os parâmetros que cada um exige
def do_list(conn):
    """GET /files - sem parâmetros."""
    return conn.request("GET", "/files", None)


def do_post(conn, key, length, file_name):
    """POST /files - body: key, length, fileName."""
    return conn.request("POST", "/files", {"key": key, "length": length, "fileName": file_name})


def do_get(conn, key, file_id):
    """GET /files/{fileId} - body: key."""
    return conn.request("GET", f"/files/{file_id}", {"key": key})


def parse_json(data):
    try:
        return json.loads(data)
    except (ValueError, TypeError):
        return None


def parse_server_metrics(data):
    obj = parse_json(data)
    m = (obj or {}).get("metrics") if isinstance(obj, dict) else None
    m = m or {}
    return {f: m.get(f) for f in SERVER_FIELDS}


def files_from_listing(data):
    obj = parse_json(data)
    if not isinstance(obj, dict):
        return None
    return obj.get("files") or []


def error_text(status, data):
    """Mensagem de erro curta a partir da resposta do servidor."""
    txt = data[:200].decode(errors="replace").strip() if data else ""
    return f"HTTP {status}: {txt}" if txt else f"HTTP {status}"


def format_server_metrics(srv, only_nonzero=True):
    parts = []
    for f in SERVER_FIELDS:
        v = srv.get(f)
        if isinstance(v, (int, float)) and (v > 0 or not only_nonzero):
            parts.append(f"{FIELD_LABELS[f]} {v / 1000:.3f} ms")
    return " | ".join(parts) if parts else "sem métricas"


def check_key(parser, key):
    n = len(key.encode())
    if n != KEY_BYTES:
        parser.error(f"a chave tem {n} bytes; o PDFer só aceita chaves de {KEY_BYTES} bytes "
                     "(responde 'HTTP 400: Key must be 16 bytes length')")


# ==========================================================================
# Parte 1 - pedidos normais (mostram a resposta)
# ==========================================================================
def cmd_list(a):
    conn = PdferConnection(a.host, a.port, a.timeout)
    try:
        status, data, ms = do_list(conn)
    finally:
        conn.close()
    if a.json:
        print(data.decode(errors="replace"))
        return 0 if status == 200 else 1
    print(f"GET /files  ->  HTTP {status}  ({ms:.2f} ms no cliente)")
    if status != 200:
        print(f"Erro: {error_text(status, data)}")
        return 1
    names = files_from_listing(data) or []
    print(f"\n{len(names)} ficheiro(s) na pasta store:")
    for i, n in enumerate(names, 1):
        print(f"  {i:4d}  {n}")
    print(f"\nServidor: {format_server_metrics(parse_server_metrics(data))}")
    return 0


def cmd_get(a):
    conn = PdferConnection(a.host, a.port, a.timeout)
    try:
        status, data, ms = do_get(conn, a.key, a.file_id)
    finally:
        conn.close()
    if a.json:
        print(data.decode(errors="replace"))
        return 0 if status == 200 else 1
    print(f"GET /files/{a.file_id}  (key={a.key})  ->  HTTP {status}  ({ms:.2f} ms no cliente)")
    if status != 200:
        print(f"Erro: {error_text(status, data)}")
        return 1
    obj = parse_json(data) or {}
    text = obj.get("text", "")
    if a.save:
        with open(a.save, "w") as fh:
            fh.write(text)
        print(f"Conteúdo guardado em {a.save}")
    print(f"\nConteúdo ({len(text)} caracteres):")
    if a.full or len(text) <= a.max_chars:
        print(text)
    else:
        print(text[:a.max_chars])
        print(f"... (mais {len(text) - a.max_chars} caracteres; use --full para ver tudo)")
    print(f"\nServidor: {format_server_metrics(parse_server_metrics(data))}")
    return 0


def cmd_post(a):
    # Nomes dos ficheiros a criar
    if a.count == 1:
        names = [a.file_name or f"{a.prefix}0001.txt"]
    else:
        width = max(4, len(str(a.count)))
        names = [f"{a.prefix}{i:0{width}d}.txt" for i in range(1, a.count + 1)]

    local = threading.local()   # uma ligação por thread
    conns, lock = [], threading.Lock()

    def get_conn():
        if not hasattr(local, "conn"):
            local.conn = PdferConnection(a.host, a.port, a.timeout)
            with lock:
                conns.append(local.conn)
        return local.conn

    def one(name):
        try:
            status, data, ms = do_post(get_conn(), a.key, a.length, name)
            return name, status, data, ms, None
        except Exception as exc:
            return name, None, None, None, f"{type(exc).__name__}: {exc}"

    print(f"POST /files  key={a.key}  length={a.length}  ficheiros={len(names)}"
          + (f"  threads={a.threads}" if len(names) > 1 else ""))
    t0 = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=a.threads) as pool:
        for name, status, data, ms, err in pool.map(one, names):
            results.append((name, status, ms, err))
            if a.json:
                print(f"{name}: {data.decode(errors='replace') if data else err}")
            elif err:
                print(f"  ERRO {name:<28} {err}")
            elif status >= 400:
                print(f"  ERRO {name:<28} {error_text(status, data)}")
            else:
                srv = format_server_metrics(parse_server_metrics(data))
                print(f"  OK   {name:<28} {ms:8.2f} ms   servidor: {srv}")
    wall = time.perf_counter() - t0
    for c in conns:
        c.close()

    ok = [r for r in results if r[3] is None and r[1] is not None and r[1] < 400]
    if len(names) > 1 and not a.json:
        print(f"\n{len(ok)} de {len(names)} ficheiro(s) criados em {wall:.2f} s "
              f"({len(ok) / wall:.1f} ficheiros/s)")
        if ok:
            lat = [r[2] for r in ok]
            print(f"Tempo por pedido: média {statistics.mean(lat):.2f} ms, máx {max(lat):.2f} ms")
    return 0 if len(ok) == len(names) else 1


# ==========================================================================
# Métricas no formato do Prometheus (implementação mínima, sem bibliotecas)
# ==========================================================================
# Limites dos "baldes" dos histogramas, em segundos (de 0,5 ms a 60 s)
BUCKETS = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
           0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]

METRIC_HELP = {
    "pdfer_client_request_duration_seconds":
        ("histogram", "Tempo de resposta medido pelo cliente, por tipo de pedido"),
    "pdfer_server_phase_duration_seconds":
        ("histogram", "Tempo de cada fase reportado pelo servidor no campo metrics"),
    "pdfer_client_requests_total":
        ("counter", "Pedidos feitos pelo cliente, por tipo e resultado"),
    "pdfer_client_files_listed":
        ("gauge", "N.º de ficheiros devolvidos pela última listagem GET /files"),
    "pdfer_client_running":
        ("gauge", "1 enquanto o cliente está a gerar carga, 0 depois"),
    "pdfer_client_run_info":
        ("gauge", "Parâmetros da execução atual (valor sempre 1)"),
}


class PromMetrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.hist = {}      # (nome, labels) -> [contagens por balde, soma, total]
        self.counters = {}  # (nome, labels) -> valor
        self.gauges = {}    # (nome, labels) -> valor

    @staticmethod
    def _key(name, labels):
        return name, tuple(sorted(labels.items()))

    def observe(self, name, labels, value):
        k = self._key(name, labels)
        with self.lock:
            h = self.hist.setdefault(k, [[0] * len(BUCKETS), 0.0, 0])
            for i, b in enumerate(BUCKETS):
                if value <= b:
                    h[0][i] += 1
            h[1] += value
            h[2] += 1

    def inc(self, name, labels, by=1):
        k = self._key(name, labels)
        with self.lock:
            self.counters[k] = self.counters.get(k, 0) + by

    def set(self, name, labels, value):
        with self.lock:
            self.gauges[self._key(name, labels)] = value

    @staticmethod
    def _fmt(labels, extra=None):
        items = list(labels) + (extra or [])
        if not items:
            return ""
        return "{" + ",".join(f'{k}="{v}"' for k, v in items) + "}"

    def render(self):
        out, seen = [], set()

        def header(name):
            if name not in seen:
                seen.add(name)
                kind, text = METRIC_HELP[name]
                out.append(f"# HELP {name} {text}")
                out.append(f"# TYPE {name} {kind}")

        with self.lock:
            for (name, labels), (counts, total, n) in sorted(self.hist.items()):
                header(name)
                for b, c in zip(BUCKETS, counts):
                    out.append(f"{name}_bucket{self._fmt(labels, [('le', repr(b))])} {c}")
                out.append(f"{name}_bucket{self._fmt(labels, [('le', '+Inf')])} {n}")
                out.append(f"{name}_sum{self._fmt(labels)} {total}")
                out.append(f"{name}_count{self._fmt(labels)} {n}")
            for (name, labels), v in sorted(self.counters.items()):
                header(name)
                out.append(f"{name}{self._fmt(labels)} {v}")
            for (name, labels), v in sorted(self.gauges.items()):
                header(name)
                out.append(f"{name}{self._fmt(labels)} {v}")
        return "\n".join(out) + "\n"


def start_metrics_server(metrics, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.rstrip("/") != "/metrics":
                self.send_error(404)
                return
            body = metrics.render().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # não encher o terminal com os pedidos do Prometheus

    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ==========================================================================
# Parte 2 - testes de pressão (mostram métricas)
# ==========================================================================
class StressRun:
    def __init__(self, args):
        self.a = args
        self.run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.rows = []
        self.lock = threading.Lock()
        self.seq = 0
        self.pool = []            # ficheiros disponíveis para os GET
        self.stop_at = None
        self.rng = random.Random(args.seed)
        self.prom = None
        if args.metrics_port:
            self.prom = PromMetrics()
            start_metrics_server(self.prom, args.metrics_port)
            self.prom.set("pdfer_client_running", {}, 0)
            self.prom.set("pdfer_client_run_info",
                          {"run_id": self.run_id, "mode": args.mode, "length": args.length,
                           "concurrency": args.threads}, 1)

    # ---- ficheiros a ler nos GET (nunca são criados aqui) ----
    def load_pool(self):
        if self.a.mode not in ("get", "mixed"):
            return
        if self.a.file:
            self.pool = list(self.a.file)
            print(f"GET a {len(self.pool)} ficheiro(s) indicado(s) com --file.", flush=True)
            return
        conn = PdferConnection(self.a.host, self.a.port, self.a.timeout)
        try:
            status, data, _ = do_list(conn)
        finally:
            conn.close()
        if status != 200:
            sys.exit(f"Erro a listar os ficheiros do servidor: {error_text(status, data)}")
        names = files_from_listing(data) or []
        if self.a.prefix:
            names = [n for n in names if n.startswith(self.a.prefix)]
        self.pool = names
        where = f" com o prefixo '{self.a.prefix}'" if self.a.prefix else ""
        if not names:
            if self.a.mode == "get" or self.a.post_ratio == 0:
                sys.exit(f"O servidor não tem ficheiros{where} para ler. Crie-os primeiro, "
                         f"por exemplo: python3 pdfer_client.py post --count 20 --length 1000")
            print(f"O servidor ainda não tem ficheiros{where}; os GET vão ler os que os "
                  f"POST deste teste criarem.", flush=True)
        else:
            print(f"GET a {len(names)} ficheiro(s) que já existem no servidor{where}.", flush=True)

    # ---- controlo partilhado entre threads ----
    def next_seq(self):
        with self.lock:
            if self.a.duration is None and self.seq >= self.a.warmup + self.a.requests:
                return None
            if self.stop_at is not None and time.time() >= self.stop_at:
                return None
            self.seq += 1
            return self.seq

    def pick_method(self):
        if self.a.mode != "mixed":
            return self.a.mode.upper()
        with self.lock:
            r = self.rng.random()
            have_files = bool(self.pool)
        if r < self.a.post_ratio:
            return "POST"
        if r < self.a.post_ratio + self.a.list_ratio:
            return "LIST"
        # num teste misto sem ficheiros ainda, este pedido passa a ser um dos POST do teste
        return "GET" if have_files else "POST"

    def pick_existing(self):
        with self.lock:
            return self.rng.choice(self.pool)

    def new_name(self, seq):
        return f"{self.a.post_prefix}{self.run_id}-{seq:06d}.txt"

    # ---- registo ----
    def record(self, seq, worker, method, file_name, start, status, data, ms, error):
        ok = error is None and 200 <= (status or 0) < 300
        srv = parse_server_metrics(data) if data else {}
        listed = ""
        if method == "LIST" and ok:
            names = files_from_listing(data)
            listed = len(names) if names is not None else ""
        row = {
            "run_id": self.run_id, "seq": seq, "worker": worker,
            "phase": "warmup" if seq <= self.a.warmup else "measure",
            "method": method,
            "length": self.a.length if method == "POST" else "",
            "file_name": file_name, "files_listed": listed,
            "start_epoch": f"{start:.6f}", "client_ms": f"{ms:.3f}" if ms is not None else "",
            "http_status": status if status is not None else "", "ok": int(ok),
            "error": error or "", "response_bytes": len(data) if data else 0,
        }
        for f in SERVER_FIELDS:
            v = srv.get(f)
            row[f"srv_{f}_us"] = "" if v is None else v
        with self.lock:
            self.rows.append(row)
            # no modo mixed, os ficheiros criados pelos POST do teste podem ser lidos
            if ok and method == "POST" and self.a.mode == "mixed" and not self.a.file:
                self.pool.append(file_name)
        if self.prom is not None:
            self.prom.inc("pdfer_client_requests_total",
                          {"method": method, "result": "ok" if ok else "error"})
            if ok and ms is not None:
                self.prom.observe("pdfer_client_request_duration_seconds",
                                  {"method": method}, ms / 1000.0)
                for f in SERVER_FIELDS:
                    v = srv.get(f)
                    if isinstance(v, (int, float)) and v > 0:
                        self.prom.observe("pdfer_server_phase_duration_seconds",
                                          {"method": method, "phase": f}, v / 1e6)
                if method == "LIST" and listed != "":
                    self.prom.set("pdfer_client_files_listed", {}, listed)
        if error and self.a.show_errors:
            print(f"  erro no pedido {seq} ({method} {file_name}): {error}", flush=True)

    # ---- threads ----
    def worker(self, wid):
        conn = PdferConnection(self.a.host, self.a.port, self.a.timeout)
        try:
            while True:
                seq = self.next_seq()
                if seq is None:
                    break
                method = self.pick_method()
                name = (self.pick_existing() if method == "GET"
                        else self.new_name(seq) if method == "POST" else "")
                start = time.time()
                status = data = ms = error = None
                try:
                    if method == "POST":
                        status, data, ms = do_post(conn, self.a.key, self.a.length, name)
                    elif method == "LIST":
                        status, data, ms = do_list(conn)
                    else:
                        status, data, ms = do_get(conn, self.a.key, name)
                    if status >= 400:
                        error = error_text(status, data)
                except Exception as exc:  # timeout, ligação recusada, etc.
                    error = f"{type(exc).__name__}: {exc}"
                    conn.close()
                self.record(seq, wid, method, name, start, status, data, ms, error)
        finally:
            conn.close()

    def run(self):
        self.load_pool()
        print(f"Teste {self.run_id}: modo={self.a.mode}"
              + (f" length={self.a.length}" if self.a.mode in ("post", "mixed") else "")
              + f" threads={self.a.threads} warmup={self.a.warmup} "
              + (f"duração={self.a.duration}s" if self.a.duration else f"pedidos={self.a.requests}"),
              flush=True)
        if self.a.duration:
            self.stop_at = time.time() + self.a.duration
        if self.prom is not None:
            self.prom.set("pdfer_client_running", {}, 1)
            print(f"Métricas Prometheus em http://0.0.0.0:{self.a.metrics_port}/metrics", flush=True)
        threads = [threading.Thread(target=self.worker, args=(w,), daemon=True)
                   for w in range(self.a.threads)]
        for t in threads:
            t.start()
        for t in threads:
            while t.is_alive():      # join com timeout para o Ctrl+C funcionar
                t.join(0.5)
        if self.prom is not None:
            self.prom.set("pdfer_client_running", {}, 0)

    # ---- saída ----
    def write_csv(self):
        size = f"-{self.a.length}" if self.a.mode in ("post", "mixed") else ""
        path = self.a.output or f"resultados-{self.a.mode}{size}-t{self.a.threads}-{self.run_id}.csv"
        new_file = not os.path.exists(path)
        with open(path, "a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
            if new_file:
                w.writeheader()
            for row in sorted(self.rows, key=lambda r: r["seq"]):
                w.writerow(row)
        return path

    def summary(self):
        meas = [r for r in self.rows if r["phase"] == "measure"]
        if not meas:
            print("Sem pedidos medidos.")
            return
        # Janela de medição: do início do primeiro pedido ao fim do último
        starts = [float(r["start_epoch"]) for r in meas]
        ends = [float(r["start_epoch"]) + float(r["client_ms"]) / 1000.0
                for r in meas if r["client_ms"] not in ("", None)]
        span = max((max(ends) if ends else max(starts)) - min(starts), 1e-6)
        print()
        print(f"Resumo (sem os {self.a.warmup} pedido(s) de aquecimento):")
        for method in ("POST", "GET", "LIST"):
            rs = [r for r in meas if r["method"] == method]
            if not rs:
                continue
            good = [r for r in rs if r["ok"] == 1]
            errs = len(rs) - len(good)
            label = {"POST": "POST /files", "GET": "GET /files/{id}", "LIST": "GET /files (listagem)"}[method]
            print(f"\n  {label}: {len(rs)} pedidos, {errs} erro(s) ({100.0 * errs / len(rs):.1f}%)")
            if not good:
                first_err = next((r["error"] for r in rs if r["error"]), "")
                print(f"    primeiro erro: {first_err}")
                continue
            lat = sorted(float(r["client_ms"]) for r in good)
            print(f"    débito:            {len(good) / span:8.1f} pedidos/s")
            print(f"    tempo cliente ms:  média {statistics.mean(lat):8.2f} | "
                  f"p50 {pct(lat, 50):8.2f} | p95 {pct(lat, 95):8.2f} | "
                  f"p99 {pct(lat, 99):8.2f} | máx {lat[-1]:8.2f}")
            for f in SERVER_FIELDS:
                vals = [float(r[f"srv_{f}_us"]) for r in good if r[f"srv_{f}_us"] not in ("", None)]
                if vals and max(vals) > 0:
                    print(f"    servidor {f:<22} média {statistics.mean(vals) / 1000:8.3f} ms")
            if method == "LIST":
                n = [r["files_listed"] for r in good if r["files_listed"] != ""]
                if n:
                    print(f"    ficheiros na listagem: {min(n)} a {max(n)}")


def pct(sorted_vals, p):
    """Percentil por interpolação linear (p entre 0 e 100)."""
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def cmd_stress(a):
    run = StressRun(a)
    try:
        run.run()
    except KeyboardInterrupt:
        print("\nInterrompido. A guardar o que foi medido...")
    path = run.write_csv()
    run.summary()
    print(f"\nCSV: {path}  ({len(run.rows)} linhas)")
    if a.metrics_port and a.metrics_linger > 0:
        print(f"A manter /metrics ativo mais {a.metrics_linger:.0f}s para o Prometheus "
              f"recolher os valores finais (Ctrl+C para sair já)...", flush=True)
        try:
            time.sleep(a.metrics_linger)
        except KeyboardInterrupt:
            pass
    return 0


# ==========================================================================
# Linha de comandos
# ==========================================================================
def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default=DEFAULT_HOST, help="endereço do servidor (default: %(default)s)")
    common.add_argument("--port", type=int, default=DEFAULT_PORT, help="porta (default: %(default)s)")
    common.add_argument("--timeout", type=float, default=120.0, help="timeout por pedido, em segundos")

    keyed = argparse.ArgumentParser(add_help=False)
    keyed.add_argument("--key", "-k", default=DEFAULT_KEY,
                       help="chave de exatamente 16 bytes (default: %(default)s)")

    raw = argparse.ArgumentParser(add_help=False)
    raw.add_argument("--json", action="store_true",
                     help="mostrar a resposta exatamente como vem do servidor")

    p = argparse.ArgumentParser(
        description="Cliente para o servidor PDFer: pedidos normais (list, get, post) "
                    "e testes de pressão (stress).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ajuda de cada comando: python3 pdfer_client.py <comando> --help")
    sub = p.add_subparsers(dest="command", required=True, metavar="comando")

    # --- list
    sp = sub.add_parser("list", parents=[common, raw],
                        help="GET /files - lista os ficheiros guardados")
    sp.set_defaults(func=cmd_list)

    # --- get
    sp = sub.add_parser("get", parents=[common, keyed, raw],
                        help="GET /files/{fileId} - mostra o conteúdo decifrado de um ficheiro")
    sp.add_argument("file_id", metavar="fileId", help="nome (id) do ficheiro, ex.: teste1.txt")
    sp.add_argument("--full", action="store_true", help="mostrar o conteúdo todo")
    sp.add_argument("--max-chars", type=int, default=500,
                    help="caracteres mostrados sem --full (default: %(default)s)")
    sp.add_argument("--save", metavar="FICHEIRO", help="guardar o conteúdo decifrado num ficheiro local")
    sp.set_defaults(func=cmd_get)

    # --- post
    sp = sub.add_parser("post", parents=[common, keyed, raw],
                        help="POST /files - cria um ou vários ficheiros (key, length, fileName)")
    sp.add_argument("file_name", metavar="fileName", nargs="?",
                    help="nome do ficheiro a criar (só quando se cria um ficheiro)")
    sp.add_argument("--length", "-l", type=int, required=True,
                    help="número de caracteres do ficheiro")
    sp.add_argument("--count", "-c", type=int, default=1,
                    help="número de ficheiros a criar (default: %(default)s)")
    sp.add_argument("--threads", "-t", type=int, default=1,
                    help="pedidos em simultâneo quando --count > 1 (default: %(default)s)")
    sp.add_argument("--prefix", default="ficheiro-",
                    help="prefixo dos nomes com --count, ex.: lote- dá lote-0001.txt (default: %(default)s)")
    sp.set_defaults(func=cmd_post)

    # --- stress
    sp = sub.add_parser("stress", parents=[common, keyed],
                        help="teste de pressão: muitos pedidos com threads; mostra métricas")
    sp.add_argument("--mode", "-m", choices=["post", "get", "list", "mixed"], required=True,
                    help="tipo de pedidos")
    sp.add_argument("--threads", "-t", "--concurrency", type=int, default=1,
                    help="pedidos em simultâneo (default: %(default)s)")
    sp.add_argument("--requests", "-n", type=int, default=100,
                    help="n.º de pedidos medidos, sem contar o aquecimento (default: %(default)s)")
    sp.add_argument("--duration", "-d", type=float, default=None,
                    help="em vez de --requests, correr durante N segundos")
    sp.add_argument("--warmup", type=int, default=5,
                    help="pedidos iniciais excluídos do resumo (default: %(default)s)")
    sp.add_argument("--length", "-l", type=int, default=1000,
                    help="caracteres de cada ficheiro criado nos POST (default: %(default)s)")
    sp.add_argument("--file", action="append", metavar="FILEID",
                    help="nos GET, ler este ficheiro (repetir para vários)")
    sp.add_argument("--prefix", metavar="PREFIXO",
                    help="nos GET, ler só os ficheiros existentes cujo nome começa por PREFIXO")
    sp.add_argument("--post-prefix", default="stress-",
                    help="prefixo dos ficheiros criados pelos POST do teste (default: %(default)s)")
    sp.add_argument("--post-ratio", type=float, default=0.5,
                    help="fração de POST no modo mixed (default: %(default)s)")
    sp.add_argument("--list-ratio", type=float, default=0.0,
                    help="fração de listagens no modo mixed; o resto são GET (default: %(default)s)")
    sp.add_argument("--seed", type=int, default=42, help="semente aleatória (reprodutibilidade)")
    sp.add_argument("--output", "-o", help="ficheiro CSV (default: nome automático; se existir, acrescenta)")
    sp.add_argument("--show-errors", action="store_true", help="mostrar cada erro à medida que acontece")
    sp.add_argument("--metrics-port", type=int, default=None,
                    help="publicar métricas para o Prometheus nesta porta (ex.: 9200)")
    sp.add_argument("--metrics-linger", type=float, default=20.0,
                    help="segundos que /metrics fica ativo no fim (default: %(default)s)")
    sp.set_defaults(func=cmd_stress)
    return p


def main():
    p = build_parser()
    a = p.parse_args()

    if hasattr(a, "key"):
        check_key(p, a.key)

    if a.command == "post":
        if a.length < 1 or a.count < 1 or a.threads < 1:
            p.error("--length, --count e --threads têm de ser >= 1")
        if a.file_name and a.count > 1:
            p.error("com --count > 1 os nomes são gerados a partir do --prefix; não indique o fileName")
    if a.command == "get" and a.max_chars < 0:
        p.error("--max-chars tem de ser >= 0")
    if a.command == "stress":
        if a.threads < 1 or a.requests < 1 or a.length < 1 or a.warmup < 0:
            p.error("--threads, --requests e --length têm de ser >= 1 e --warmup >= 0")
        if not (0.0 <= a.post_ratio <= 1.0 and 0.0 <= a.list_ratio <= 1.0) \
                or a.post_ratio + a.list_ratio > 1.0:
            p.error("--post-ratio e --list-ratio têm de estar entre 0 e 1 e somar no máximo 1")
        if (a.file or a.prefix) and a.mode not in ("get", "mixed"):
            p.error("--file e --prefix só se aplicam aos modos get e mixed")
        if a.file and a.prefix:
            p.error("use --file ou --prefix, não os dois")

    sys.exit(a.func(a))


if __name__ == "__main__":
    main()