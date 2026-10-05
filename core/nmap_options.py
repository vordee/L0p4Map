"""Nmap scan presets and validation shared by the command preview and runner."""

import re
import shlex

TCP_FLAGS = ("-sS", "-sT", "-sN", "-sX")
PORT_FLAGS = ("", "-F", "-p-")
TIMING_FLAGS = ("-T1", "-T2", "-T3", "-T4", "-T5")
SCAN_PRESETS = {
    "basic": ("-sT", "-F", "--open", "-T3"),
    "complete": ("-sS", "-sU", "-p-", "-sV", "-O", "-sC", "--reason", "-T3"),
}
# Values of these options may look like scan flags; do not interpret them as options.
VALUE_OPTIONS = {
    "--script-args", "--script-args-file", "--exclude", "--excludefile", "-iL",
    "-oN", "-oX", "-oG", "-oA", "-oS", "--datadir", "--servicedb", "--versiondb",
    "--dns-servers", "-e", "-S", "--source-port", "-g", "--proxies",
    "--host-timeout", "--max-retries", "--min-rate", "--max-rate", "--data-string",
}


def build_scan_command(selected, custom, target):
    target = target.strip()
    if not target or target.startswith("-"):
        raise ValueError("Informe um alvo válido antes de executar.")
    args = []
    for flag in selected:
        args.extend(shlex.split(flag))
    try:
        args.extend(shlex.split(custom))
    except ValueError as exc:
        raise ValueError("Revise as aspas das flags manuais.") from exc

    tcp = set()
    sctp = set()
    udp = False
    os_detection = False
    os_guess = False
    non_port_scan = False
    ports = []
    timings = set()
    scripts = []
    cleaned = []
    default_script_indices = set()
    default_scripts = False
    index = 0
    while index < len(args):
        token = args[index]
        index += 1
        if token == "--script" or token.startswith("--script="):
            if token == "--script":
                if index >= len(args) or args[index].startswith("-"):
                    raise ValueError("Informe o nome ou categoria após --script.")
                value = args[index]
                index += 1
            else:
                value = token.partition("=")[2]
            if not value:
                raise ValueError("Informe uma seleção de scripts válida.")
            if value not in scripts:
                scripts.append(value)
            continue
        cleaned.append(token)
        if token == "-sC":
            default_script_indices.add(len(cleaned) - 1)
        if token in VALUE_OPTIONS:
            if index >= len(args):
                raise ValueError(f"Informe um valor após {token}.")
            cleaned.append(args[index])
            index += 1
            continue
        os_detection |= token in ("-O", "-A")
        os_guess |= token == "--osscan-guess"
        default_scripts |= token == "-A"
        if token == "-s":
            if index >= len(args):
                raise ValueError("Informe o método após -s.")
            modes = args[index]
            cleaned.append(modes)
            index += 1
        elif token.startswith("-sI"):
            modes = "I"
            if token == "-sI":
                if index >= len(args):
                    raise ValueError("Informe o host do idle scan após -sI.")
                cleaned.append(args[index])
                index += 1
        else:
            match = re.fullmatch(r"-s([A-Za-z]+)", token)
            modes = match.group(1) if match else ""
        tcp.update(set(modes) & set("STNAWFMXI"))
        sctp.update(set(modes) & set("YZ"))
        udp |= "U" in modes
        non_port_scan |= bool(set(modes) & set("nLPO"))
        default_scripts |= "C" in modes
        if token.startswith("-b"):
            tcp.add("b")
            if token == "-b":
                if index >= len(args):
                    raise ValueError("Informe o servidor FTP após -b.")
                cleaned.append(args[index])
                index += 1
        if token == "-F" or token.startswith("-p") or token.split("=")[0] in ("--top-ports", "--port-ratio"):
            ports.append(token)
            if token in ("-p", "--top-ports", "--port-ratio"):
                if index >= len(args) or args[index].startswith("-"):
                    raise ValueError(f"Informe a faixa de portas após {token}.")
                cleaned.append(args[index])
                index += 1
        if token.startswith("-T"):
            timing = token[2:]
            if not timing:
                if index >= len(args):
                    raise ValueError("Informe a velocidade após -T.")
                timing = args[index]
                cleaned.append(timing)
                index += 1
            timing = {"paranoid": "0", "sneaky": "1", "polite": "2", "normal": "3",
                      "aggressive": "4", "insane": "5"}.get(timing.lower(), timing)
            timings.add(timing)

    if len(tcp) > 1:
        raise ValueError("Escolha apenas um método TCP. UDP pode ser combinado com ele.")
    if len(sctp) > 1:
        raise ValueError("Escolha apenas um método SCTP.")
    if non_port_scan and (tcp or sctp or ports or udp):
        raise ValueError("Modo de descoberta/listagem/IP não pode ser combinado com varredura de portas.")
    if len(ports) > 1:
        raise ValueError("Escolha apenas uma faixa de portas: rápida, todas ou flags manuais.")
    if len(timings) > 1:
        raise ValueError("Escolha apenas um nível de velocidade.")
    if os_guess and not os_detection:
        raise ValueError("OS guess exige detecção de sistema (-O ou -A).")
    if scripts:
        if default_scripts and "default" not in scripts:
            scripts.insert(0, "default")
        cleaned = [flag for index, flag in enumerate(cleaned) if index not in default_script_indices]
        cleaned.extend(("--script", ",".join(scripts)))
    return ["nmap", *cleaned, target]
