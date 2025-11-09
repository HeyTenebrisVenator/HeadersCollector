#!/usr/bin/env python3
"""
collect_headers.py

Ferramenta para coletar headers das respostas HTTP de múltiplos domínios/URLs,
salvar em TXT ou CSV, com flags de linha de comando e pool de workers.

Formato de saída (TXT):
{domínio} | {Header-Name}: {value}

Formato CSV: colunas -> domain,header_name,header_value

Exemplos:
python3 collect_headers.py -u https://example.com -o out.txt
python3 collect_headers.py -i targets.txt --csv -o headers.csv -w 30 --strip

Requisitos:
- Python 3.8+
- requests

Instalação:
pip install requests

"""

import argparse
import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

DEFAULT_STRIP_HEADERS = {
    'server',
    'x-powered-by',
    'set-cookie',
    'cookie',
    'date',
    'connection',
    'transfer-encoding',
    'keep-alive',
    'proxy-connection',
    'via',
    'expires',
}

DEFAULT_KEEP_HEADERS = {
    'content-type',
    'content-length',
    'cache-control',
    'etag',
    'last-modified',
    'x-request-id',
    'x-frame-options',
    'strict-transport-security',
    'content-security-policy',
}


def normalize_domain(url_or_domain: str) -> str:
    url = url_or_domain.strip()
    if not url:
        return ''
    if url.startswith('http://') or url.startswith('https://'):
        return url
    return 'https://' + url


def fetch_headers(url: str, timeout: int = 8, allow_redirects: bool = True, verify: bool = True):
    domain = url
    session = requests.Session()
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify)
        if not resp.headers:
            resp = session.get(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify)
    except requests.RequestException as e:
        return domain, None, str(e)

    headers = {k: v for k, v in resp.headers.items()}
    return domain, headers, None


def filter_headers(headers: dict, strip_set: set = None, keep_set: set = None):
    if headers is None:
        return None
    strip_set = set(h.lower() for h in (strip_set or DEFAULT_STRIP_HEADERS))
    keep_set = set(h.lower() for h in (keep_set or DEFAULT_KEEP_HEADERS))

    out = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in keep_set:
            out[k] = v
            continue
        if kl in strip_set:
            continue
        # se não está explicitamente na strip_set, manteha
        out[k] = v
    return out


def write_txt_line(out_file, domain: str, headers: dict):
    if headers is None:
        out_file.write(f"{domain} | ERROR: no response or request failed\n")
        return
    for k, v in headers.items():
        # cada header em uma linha no formato pedido
        out_file.write(f"{domain} | {k}: {v}\n")


def write_csv_rows(csv_writer, domain: str, headers: dict):
    if headers is None:
        csv_writer.writerow([domain, 'ERROR', 'no response or request failed'])
        return
    for k, v in headers.items():
        csv_writer.writerow([domain, k, v])


def process_target(target: str, timeout: int, allow_redirects: bool, verify: bool, strip_set, keep_set):
    url = normalize_domain(target)
    domain_for_save = urlparse(url).netloc or url
    domain, headers, error = fetch_headers(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify)
    if error is not None:
        return domain_for_save, None, error
    headers = filter_headers(headers, strip_set=strip_set, keep_set=keep_set)
    return domain_for_save, headers, None


def main():
    parser = argparse.ArgumentParser(description='Coletor de headers HTTP com pool de workers')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input-file', help='Arquivo com targets (um por linha)')
    group.add_argument('-u', '--url', help='URL ou domínio único (ex: example.com ou https://example.com)')
    parser.add_argument('-o', '--output', default='headers.txt', help='Arquivo de saída (txt ou csv ex: out.csv)')
    parser.add_argument('--csv', action='store_true', help='Salvar em CSV (colunas: domain,header_name,header_value)')
    parser.add_argument('-w', '--workers', type=int, default=20, help='Número de workers no pool (padrão 20)')
    parser.add_argument('-t', '--timeout', type=int, default=8, help='Timeout em segundos para cada requisição (padrão 8)')
    parser.add_argument('--no-verify', action='store_true', help='Desabilitar verificação de certificado TLS (inseguro)')
    parser.add_argument('--no-redirects', action='store_true', help='Não seguir redirects')
    parser.add_argument('--strip', action='store_true', help='Remover cabeçalhos considerados desnecessários (padrão: ON quando usado)')
    parser.add_argument('--keep', help='Lista separada por vírgula de headers a sempre manter (ex: Content-Type,X-Request-Id)')
    parser.add_argument('--remove', help='Lista separada por vírgula de headers adicionais a remover')
    parser.add_argument('--max', type=int, default=0, help='Máximo de targets a processar (0 = todos)')
    args = parser.parse_args()

    # Carregar targets
    targets = []
    if args.input_file:
        try:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    s = line.strip()
                    if s:
                        targets.append(s)
        except Exception as e:
            print(f"Erro ao abrir arquivo de input: {e}")
            sys.exit(1)
    else:
        targets = [args.url.strip()]

    if args.max and args.max > 0:
        targets = targets[:args.max]

    strip_set = set(DEFAULT_STRIP_HEADERS) if args.strip else set()
    keep_set = set(DEFAULT_KEEP_HEADERS)
    if args.remove:
        for h in args.remove.split(','):
            strip_set.add(h.strip().lower())
    if args.keep:
        keep_set = set(h.strip().lower() for h in args.keep.split(','))

    out_path = args.output
    use_csv = args.csv or out_path.lower().endswith('.csv')

    start = time.time()
    print(f"Starting: {len(targets)} targets, workers={args.workers}, timeout={args.timeout}, csv={use_csv}")

    if use_csv:
        fout = open(out_path, 'w', newline='', encoding='utf-8')
        csv_writer = csv.writer(fout)
        csv_writer.writerow(['domain', 'header_name', 'header_value'])
    else:
        fout = open(out_path, 'w', encoding='utf-8')
        csv_writer = None

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for target in targets:
            futures.append(executor.submit(process_target, target, args.timeout, not args.no_redirects, not args.no_verify, strip_set, keep_set))

        for fut in as_completed(futures):
            try:
                domain, headers, error = fut.result()
            except Exception as e:
                # erro inesperado no worker
                print(f"Worker exception: {e}")
                continue

            if error:
                # log de erro no arquivo
                if use_csv:
                    csv_writer.writerow([domain, 'ERROR', error])
                else:
                    fout.write(f"{domain} | ERROR: {error}\n")
                print(f"{domain} -> ERROR: {error}")
                continue

            if use_csv:
                write_csv_rows(csv_writer, domain, headers)
            else:
                write_txt_line(fout, domain, headers)
            print(f"{domain} -> saved {0 if headers is None else len(headers)} headers")

    fout.close()
    elapsed = time.time() - start
    print(f"Done in {elapsed:.2f}s. Output: {out_path}")


if __name__ == '__main__':
    main()
