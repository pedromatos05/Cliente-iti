#!/usr/bin/env python3
"""
pdfer_client.py - Cliente de carga para o servidor PDFer (ITI 2025/2026).

Faz pedidos ao PDFer e mede o tempo de cada um do lado do cliente:
  POST /files            -> "POST": gera, cifra e guarda um ficheiro
  GET  /files/{fileId}   -> "GET":  lê e decifra um ficheiro
  GET  /files            -> "LIST": lista os ficheiros guardados
Guarda também guarda as métricas devolvidas pelo servidor
e escreve tudo num CSV (uma linha por pedido). No fim mostra um resumo
separado para POST e GET.

Opcionalmente (--metrics-port), publica as métricas no formato do Prometheus
em http://<node2>:<porta>/metrics, para as ver ao vivo no Grafana.

Usa apenas a biblioteca padrão do Python 3 (não é preciso instalar nada).

Exemplos:
  # 100 POST de 1000 caracteres, 1 de cada vez
  python3 pdfer_client.py --mode post --length 1000 --requests 100

  # 200 GET a 20 ficheiros criados antes, 4 pedidos em simultâneo
  python3 pdfer_client.py --mode get --length 1000 --prepare 20 --requests 200 --concurrency 4

  # 100 listagens com 1000 ficheiros na pasta (efeito do n.º de ficheiros)
  python3 pdfer_client.py --mode list --prepare 1000 --length 100 --requests 100

  # carga mista: 30% POST, 10% LIST, 60% GET durante 60 segundos
  python3 pdfer_client.py --mode mixed --post-ratio 0.3 --list-ratio 0.1 --duration 60 --concurrency 8
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
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVER_FIELDS = [
    "total",
    "readFileSystemEntries",
    "generateFile",
    "encryption",
    "writeFile",
    "readFile",
    "decryption",
]

CSV_COLUMNS = [
    "run_id", "seq", "worker", "phase", "method", "length", "file_name", "files_listed",
    "start_epoch", "client_ms", "http_status", "ok", "error", "response_bytes",
] + [f"srv_{f}_us" for f in SERVER_FIELDS]


# --------------------------------------------------------------------------
# Métricas no formato do Prometheus (implementação mínima, sem bibliotecas)
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# Comunicação com o servidor
# --------------------------------------------------------------------------
class PdferConnection:
    """Uma ligação HTTP persistente (keep-alive) por thread."""

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


def do_post(conn, key, length, file_name):
    return conn.request("POST", "/files",
                        {"key": key, "length": length, "fileName": file_name})


def do_get(conn, key, file_name):
    return conn.request("GET", f"/files/{file_name}", {"key": key})


def do_list(conn):
    return conn.request("GET", "/files", None)


def files_listed(data):
    """N.º de ficheiros devolvidos por GET /files (0 se a pasta estiver vazia)."""
    try:
        return len(json.loads(data).get("files") or [])
    except (ValueError, AttributeError, TypeError):
        return ""


def parse_server_metrics(data):
    try:
        m = json.loads(data).get("metrics", {}) or {}
    except (ValueError, AttributeError):
        return {}
    return {f: m.get(f) for f in SERVER_FIELDS}


# --------------------------------------------------------------------------
# Execução da carga
# --------------------------------------------------------------------------
class LoadRun:
    def __init__(self, args):
        self.a = args
        self.run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.rows = []
        self.lock = threading.Lock()
        self.seq = 0
        self.created = []          # ficheiros disponíveis para GET
        self.stop_at = None
        self.rng = random.Random(args.seed)
        self.prom = None
        if args.metrics_port:
            self.prom = PromMetrics()
            start_metrics_server(self.prom, args.metrics_port)
            self.prom.set("pdfer_client_running", {}, 0)
            self.prom.set("pdfer_client_run_info",
                          {"run_id": self.run_id, "mode": args.mode, "length": args.length,
                           "concurrency": args.concurrency}, 1)

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
        if self.a.mode == "post":
            return "POST"
        if self.a.mode == "get":
            return "GET"
        if self.a.mode == "list":
            return "LIST"
        with self.lock:
            r = self.rng.random()
        if r < self.a.post_ratio:
            return "POST"
        if r < self.a.post_ratio + self.a.list_ratio:
            return "LIST"
        return "GET"

    def pick_existing(self):
        with self.lock:
            return self.rng.choice(self.created) if self.created else None

    def new_name(self, seq):
        return f"{self.a.prefix}-{self.run_id}-{seq:06d}.txt"

    # ---- registo ----
    def record(self, seq, worker, method, file_name, start, status, data, ms, error):
        ok = error is None and 200 <= (status or 0) < 300
        srv = parse_server_metrics(data) if data else {}
        row = {
            "run_id": self.run_id, "seq": seq, "worker": worker,
            "phase": "warmup" if seq <= self.a.warmup else "measure",
            "method": method, "length": "" if method == "LIST" else self.a.length,
            "file_name": file_name, "files_listed": files_listed(data) if method == "LIST" else "",
            "start_epoch": f"{start:.6f}", "client_ms": f"{ms:.3f}" if ms is not None else "",
            "http_status": status if status is not None else "", "ok": int(ok),
            "error": error or "", "response_bytes": len(data) if data else 0,
        }
        for f in SERVER_FIELDS:
            v = srv.get(f)
            row[f"srv_{f}_us"] = "" if v is None else v
        with self.lock:
            self.rows.append(row)
            if ok and method == "POST":
                self.created.append(file_name)
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
                if method == "LIST" and row["files_listed"] != "":
                    self.prom.set("pdfer_client_files_listed", {}, row["files_listed"])

    # ---- threads ----
    def worker(self, wid):
        conn = PdferConnection(self.a.host, self.a.port, self.a.timeout)
        try:
            while True:
                seq = self.next_seq()
                if seq is None:
                    break
                method = self.pick_method()
                if method == "GET":
                    name = self.pick_existing()
                    if name is None:          # ainda não há ficheiros: faz POST
                        method, name = "POST", self.new_name(seq)
                elif method == "LIST":
                    name = ""
                else:
                    name = self.new_name(seq)
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
                        error = f"HTTP {status}: {data[:120].decode(errors='replace').strip()}"
                except Exception as exc:  # timeout, ligação recusada, etc.
                    error = f"{type(exc).__name__}: {exc}"
                    conn.close()
                self.record(seq, wid, method, name, start, status, data, ms, error)
        finally:
            conn.close()

    def prepare(self):
        """Cria ficheiros antes da medição (necessário para os GET)."""
        n = self.a.prepare
        if n <= 0:
            return
        print(f"A preparar {n} ficheiro(s) de {self.a.length} caracteres...", flush=True)
        conn = PdferConnection(self.a.host, self.a.port, self.a.timeout)
        try:
            for i in range(1, n + 1):
                name = f"{self.a.prefix}-{self.run_id}-prep{i:05d}.txt"
                status, data, _ = do_post(conn, self.a.key, self.a.length, name)
                if status >= 300:
                    sys.exit(f"Erro a preparar ficheiros: HTTP {status} {data[:200]!r}")
                self.created.append(name)
        finally:
            conn.close()

    def run(self):
        self.prepare()
        print(f"Run {self.run_id}: modo={self.a.mode} length={self.a.length} "
              f"concorrência={self.a.concurrency} warmup={self.a.warmup} "
              + (f"duração={self.a.duration}s" if self.a.duration else f"pedidos={self.a.requests}"),
              flush=True)
        if self.a.duration:
            self.stop_at = time.time() + self.a.duration
        if self.prom is not None:
            self.prom.set("pdfer_client_running", {}, 1)
            print(f"Métricas Prometheus em http://0.0.0.0:{self.a.metrics_port}/metrics", flush=True)
        t0 = time.time()
        threads = [threading.Thread(target=self.worker, args=(w,), daemon=True)
                   for w in range(self.a.concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            while t.is_alive():      # join com timeout para o Ctrl+C funcionar
                t.join(0.5)
        self.wall = time.time() - t0
        if self.prom is not None:
            self.prom.set("pdfer_client_running", {}, 0)

    # ---- saída ----
    def write_csv(self):
        path = self.a.output or f"resultados-{self.a.mode}-{self.a.length}-c{self.a.concurrency}-{self.run_id}.csv"
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
        starts = [float(r["start_epoch"]) for r in meas]
        span = max(max(starts) - min(starts), 1e-9)
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


# --------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Cliente de carga para o PDFer")
    p.add_argument("--host", default="192.168.57.11", help="endereço do servidor (default: %(default)s)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--mode", choices=["post", "get", "list", "mixed"], default="post",
                   help="post = criar ficheiros; get = ler ficheiros; list = listar a pasta; "
                        "mixed = mistura (default: %(default)s)")
    p.add_argument("--length", type=int, default=1000, help="caracteres por ficheiro (default: %(default)s)")
    p.add_argument("--requests", type=int, default=100,
                   help="n.º de pedidos medidos, sem contar o aquecimento (default: %(default)s)")
    p.add_argument("--duration", type=float, default=None,
                   help="em vez de --requests, correr durante N segundos")
    p.add_argument("--concurrency", type=int, default=1, help="pedidos em simultâneo (default: %(default)s)")
    p.add_argument("--warmup", type=int, default=5,
                   help="pedidos iniciais excluídos do resumo (default: %(default)s)")
    p.add_argument("--prepare", type=int, default=None,
                   help="ficheiros a criar antes de medir (default: 20 em get/mixed, 0 em post/list)")
    p.add_argument("--post-ratio", type=float, default=0.5,
                   help="fração de POST no modo mixed (default: %(default)s)")
    p.add_argument("--list-ratio", type=float, default=0.0,
                   help="fração de listagens (GET /files) no modo mixed; o resto são GET de "
                        "ficheiros (default: %(default)s)")
    p.add_argument("--key", default="chave-de-teste16", help="chave de 16, 24 ou 32 caracteres")
    p.add_argument("--prefix", default="cli", help="prefixo dos nomes de ficheiro")
    p.add_argument("--timeout", type=float, default=120.0, help="timeout por pedido em segundos")
    p.add_argument("--seed", type=int, default=42, help="semente aleatória (reprodutibilidade)")
    p.add_argument("--output", help="ficheiro CSV (default: nome automático; se existir, acrescenta linhas)")
    p.add_argument("--metrics-port", type=int, default=None,
                   help="publica métricas para o Prometheus nesta porta (ex.: 9200)")
    p.add_argument("--metrics-linger", type=float, default=20.0,
                   help="segundos que a página /metrics fica ativa no fim, para o "
                        "Prometheus recolher os últimos valores (default: %(default)s)")
    a = p.parse_args()

    if len(a.key.encode()) not in (16, 24, 32):
        p.error(f"a chave tem {len(a.key.encode())} bytes; o AES exige 16, 24 ou 32")
    if a.concurrency < 1 or a.requests < 1 or a.length < 1:
        p.error("--concurrency, --requests e --length têm de ser >= 1")
    if not (0.0 <= a.post_ratio <= 1.0 and 0.0 <= a.list_ratio <= 1.0) or a.post_ratio + a.list_ratio > 1.0:
        p.error("--post-ratio e --list-ratio têm de estar entre 0 e 1 e somar no máximo 1")
    if a.prepare is None:
        a.prepare = 0 if a.mode in ("post", "list") else 20

    run = LoadRun(a)
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


if __name__ == "__main__":
    main()
