#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = BASE_DIR / "scripts"
RESULTS_DIR = BASE_DIR / "results"
CONFIG_FILE = BASE_DIR / "config.json"


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def load_config() -> dict[str, Any]:
    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dirs() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def write_list_file(items: list[str], outfile: Path) -> None:
    with outfile.open("w", encoding="utf-8") as f:
        for item in items:
            f.write(f"{item}\n")


def parse_discovery_report(text: str) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if line.startswith("Nmap scan report for "):
            if current:
                hosts.append(current)

            text_part = line.replace("Nmap scan report for ", "", 1)
            m = re.match(r"(.+?) \((\d+\.\d+\.\d+\.\d+)\)$", text_part)
            if m:
                current = {
                    "hostname": m.group(1),
                    "ip": m.group(2),
                    "mac": None,
                    "vendor": None,
                }
            else:
                current = {
                    "hostname": None,
                    "ip": text_part,
                    "mac": None,
                    "vendor": None,
                }

        elif line.startswith("MAC Address:") and current:
            m = re.match(r"MAC Address:\s+([0-9A-F:]+)\s+\((.+)\)", line, re.I)
            if m:
                current["mac"] = m.group(1)
                current["vendor"] = m.group(2)

    if current:
        hosts.append(current)

    return [h for h in hosts if h.get("ip")]


def parse_open_ports(nmap_text: str) -> list[int]:
    open_ports: list[int] = []
    for line in nmap_text.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open", line.strip())
        if m:
            open_ports.append(int(m.group(1)))
    return open_ports


def score_candidate(host: dict[str, Any], open_ports: list[int], service_text: str, http_text: str, rtsp_text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    vendor = (host.get("vendor") or "").lower()

    if 80 in open_ports:
        score += 1
        reasons.append("porta 80 aberta")
    if 554 in open_ports:
        score += 3
        reasons.append("porta 554 aberta")
    if 8899 in open_ports:
        score += 1
        reasons.append("porta 8899 aberta")

    if any(x in vendor for x in ["alto", "shenzhen", "hikvision", "dahua", "ipc", "camera"]):
        score += 1
        reasons.append(f"vendor sugestivo: {host.get('vendor')}")

    if "jdbhttpd" in http_text.lower() or "jdbhttpd" in service_text.lower():
        score += 2
        reasons.append("banner HTTP sugere jdbhttpd")

    if "RTSP/1.0" in rtsp_text:
        score += 3
        reasons.append("resposta RTSP detectada")

    return score, reasons


def summarize_findings(open_ports: list[int], service_text: str, http_text: str, rtsp_text: str, availability_text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if 80 in open_ports and 443 not in open_ports:
        findings.append({
            "category": "network_exposure",
            "severity": "high",
            "title": "Interface HTTP sem HTTPS",
            "evidence": "Porta 80 aberta e ausência de HTTPS identificado na porta 443.",
            "recommendation": "Avaliar uso de HTTPS/TLS para interface administrativa."
        })

    if 554 in open_ports:
        findings.append({
            "category": "stream_exposure",
            "severity": "high",
            "title": "Serviço RTSP exposto",
            "evidence": "Porta 554/TCP aberta.",
            "recommendation": "Validar autenticação do stream e verificar transmissão sem criptografia."
        })

    if "jdbhttpd" in http_text.lower() or "jdbhttpd" in service_text.lower():
        findings.append({
            "category": "embedded_web_server",
            "severity": "medium",
            "title": "Servidor web embarcado identificado",
            "evidence": "Cabeçalhos ou enumeração sugerem jdbhttpd.",
            "recommendation": "Verificar firmware e atualização do dispositivo."
        })

    if "RTSP/1.0" in rtsp_text:
        findings.append({
            "category": "protocol_exposure",
            "severity": "medium",
            "title": "RTSP respondeu a sondas",
            "evidence": "Foram observadas respostas RTSP na enumeração.",
            "recommendation": "Testar caminhos válidos de stream em ambiente controlado."
        })

    if availability_text.strip():
        findings.append({
            "category": "availability",
            "severity": "info",
            "title": "Serviço HTTP respondeu ao teste leve de disponibilidade",
            "evidence": "Foram registradas respostas durante teste leve de disponibilidade.",
            "recommendation": "Comparar latências e estabilidade entre dispositivos."
        })

    return findings


def save_json(data: Any, outfile: Path) -> None:
    with outfile.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main() -> int:
    ensure_dirs()
    cfg = load_config()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RESULTS_DIR / f"run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    http_paths_file = run_dir / "http_paths.txt"
    rtsp_paths_file = run_dir / "rtsp_paths.txt"
    write_list_file(cfg["http_paths"], http_paths_file)
    write_list_file(cfg["rtsp_paths"], rtsp_paths_file)

    # Etapa 1 - descoberta
    discovery_out = run_dir / "discovery.txt"
    print(f"[+] Descobrindo hosts em {cfg['network']}")
    rc, out, err = run_cmd([
        str(SCRIPTS_DIR / "discover.sh"),
        cfg["network"],
        str(discovery_out),
    ])
    if rc != 0:
        print(err)
        return rc

    discovery_text = discovery_out.read_text(encoding="utf-8", errors="replace")
    hosts = parse_discovery_report(discovery_text)

    if not hosts:
        print("[!] Nenhum host encontrado.")
        return 1

    print(f"[+] Hosts encontrados: {len(hosts)}")

    candidates: list[dict[str, Any]] = []
    all_reports: list[dict[str, Any]] = []

    for host in hosts:
        ip = host["ip"]
        print(f"[+] Processando host {ip}")

        host_dir = run_dir / ip.replace(".", "_")
        host_dir.mkdir(parents=True, exist_ok=True)

        portscan_out = host_dir / "portscan.txt"
        service_out = host_dir / "service_scan.txt"
        http_out = host_dir / "http_enum.txt"
        rtsp_out = host_dir / "rtsp_enum.txt"
        capture_out = host_dir / "traffic_capture.pcap"
        availability_out = host_dir / "availability.txt"

        run_cmd([
            str(SCRIPTS_DIR / "portscan.sh"),
            ip,
            cfg["ports"],
            str(portscan_out),
        ])

        run_cmd([
            str(SCRIPTS_DIR / "service_scan.sh"),
            ip,
            cfg["ports"],
            str(service_out),
        ])

        run_cmd([
            str(SCRIPTS_DIR / "http_enum.sh"),
            ip,
            str(http_paths_file),
            str(http_out),
        ])

        run_cmd([
            str(SCRIPTS_DIR / "rtsp_enum.sh"),
            ip,
            str(rtsp_paths_file),
            str(rtsp_out),
        ])
        
        auth_out = host_dir / "auth_test.txt"

        run_cmd([
            str(SCRIPTS_DIR / "auth_test.sh"),
            ip,
            str(auth_out),
        ])

        service_text = service_out.read_text(encoding="utf-8", errors="replace") if service_out.exists() else ""
        portscan_text = portscan_out.read_text(encoding="utf-8", errors="replace") if portscan_out.exists() else ""
        http_text = http_out.read_text(encoding="utf-8", errors="replace") if http_out.exists() else ""
        rtsp_text = rtsp_out.read_text(encoding="utf-8", errors="replace") if rtsp_out.exists() else ""
        
        open_ports = parse_open_ports(portscan_text)
        score, reasons = score_candidate(host, open_ports, service_text, http_text, rtsp_text)

        candidate = {
            "ip": ip,
            "hostname": host.get("hostname"),
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "open_ports": open_ports,
            "score": score,
            "reasons": reasons,
            "selected": score >= cfg["min_candidate_score"],
        }
        candidates.append(candidate)

        if score >= cfg["min_candidate_score"]:
            print(f"    [*] Candidato selecionado (score={score})")

            run_cmd([
                str(SCRIPTS_DIR / "capture.sh"),
                ip,
                str(cfg["capture_duration"]),
                str(capture_out),
            ])

            run_cmd([
                str(SCRIPTS_DIR / "availability.sh"),
                ip,
                str(cfg["availability_requests"]),
                str(cfg["availability_delay_seconds"]),
                str(availability_out),
            ])

            availability_text = availability_out.read_text(encoding="utf-8", errors="replace") if availability_out.exists() else ""

            findings = summarize_findings(
                open_ports=open_ports,
                service_text=service_text,
                http_text=http_text,
                rtsp_text=rtsp_text,
                availability_text=availability_text,
            )

            report = {
                "host": host,
                "open_ports": open_ports,
                "score": score,
                "reasons": reasons,
                "findings": findings,
                "files": {
                    "portscan": str(portscan_out),
                    "service_scan": str(service_out),
                    "http_enum": str(http_out),
                    "rtsp_enum": str(rtsp_out),
                    "capture": str(capture_out),
                    "availability": str(availability_out),
                },
            }
            all_reports.append(report)

            save_json(report, host_dir / "report.json")

    save_json(candidates, run_dir / "classified_candidates.json")
    save_json(all_reports, run_dir / "consolidated_reports.json")

    print(f"[+] Execução concluída. Resultados em: {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
