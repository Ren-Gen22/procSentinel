# ProcSentinel: A Hybrid Process Monitoring System for Linux Threat Detection

## 1. Introduction

Procwatch is a lightweight, heuristic-based process monitoring tool for Linux. It is designed to identify suspicious processes running on your system by analyzing various process attributes and assigning a risk score. When a process's score exceeds a configurable threshold, `procwatch` can alert you, kill the process, and/or dump its artifacts for later forensic analysis.

### 1.1 Contributions

The main contributions of this work include: 

First, a comprehensive heuristic-based detection framework that identifies suspicious process behaviors through configurable weighted scoring mechanisms. Second, an integrated machine learning component that provides anomaly detection capabilities using baseline models trained on normal system behavior. Third, a flexible architecture that enables real-time process monitoring with configurable response actions including alerting, process termination, and forensic artifact collection.

### 1.2 Scope

This system addresses the detection of various threat categories including fileless malware execution, processes running from temporary directories, memory manipulation techniques, process masquerading, and anomalous network behaviors. The tool operates entirely within the Linux `/proc` filesystem, providing lightweight monitoring without requiring kernel modifications or specialized hardware.

## 2. System Overview

Procwatch operates in two main modes: `scan` and `train`.

### 2.1 Scan Mode

The scan mode implements a four-stage pipeline for threat detection. First, during the **Process Collection** stage, the system iterates through all running processes in the `/proc` filesystem. Second, in the **Analysis** stage, it gathers comprehensive information about each process including its executable, command line, memory maps, parent process, environment variables, resource usage, and network connections. Third, during **Heuristic Scoring**, the system applies a set of heuristics to each process to identify suspicious characteristics, where each matching heuristic adds a weighted score to the process's total risk score with configurable weights. Fourth, in the **ML Scoring** stage, if a trained model is available, `procwatch` calculates an anomaly score based on the process's features, which is then multiplied by a configurable weight and added to the total score.

### 2.2 Action Stage

If a process's total score exceeds the configured `min_score`, it is flagged as a finding. The system can then execute multiple response actions based on configuration. These actions include printing a detailed alert to the console, killing the process using appropriate signals, dumping the process's artifacts to a specified directory for forensic analysis, or stopping the scan after detecting the first suspicious process.

### 2.3 Train Mode

In train mode, `procwatch` collects feature data from all running processes for a specified duration. It then uses this data to train a baseline model for anomaly detection. This model can then be used in scan mode to improve the detection of suspicious processes. Two types of models are supported: a simple `ZScoreModel` and a more advanced `IsolationForestModel` from `scikit-learn`.

---

## 3. Architecture

The project is organized into a modular directory structure that separates concerns across multiple components.

```
.
├── procwatch.py
├── procwatch/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── features.py
│   ├── heuristics.py
│   ├── ml.py
│   ├── models.py
│   ├── network.py
│   ├── proc.py
│   ├── utils.py
│   └── whitelist.py
├── README.md
└── GUIDE.md
```

The main entry point `procwatch.py` provides the command-line interface for the tool. The core logic resides within the `procwatch/` directory, which contains several specialized modules. The `__init__.py` file initializes the package structure. The `cli.py` module defines the command-line interface and its arguments. Configuration management is handled by `config.py`, which loads settings from YAML files. Feature extraction for machine learning is implemented in `features.py`. The `heuristics.py` module defines the scoring rules used to identify suspicious processes. Machine learning model training and inference logic is contained in `ml.py`. Data structures and models are defined in `models.py`. Network connection analysis is performed by `network.py`. The `proc.py` module handles all interactions with the Linux `/proc` filesystem. Utility functions used throughout the application are provided by `utils.py`. Finally, `whitelist.py` implements the logic for whitelisting trusted processes and users.

---


## 4. Hybrid Detection Methodology

Procwatch uses a combination of heuristics and machine learning to detect suspicious processes.

### 4.1 Heuristic-based Detection

The system employs multiple heuristics to score processes, with configurable weights specified in the `procwatch.yaml` file. 

The **Deleted Executable** heuristic identifies processes whose executable files have been deleted from disk while still running, a common technique used by malware to hide its presence. **Fileless Execution (memfd)** detection targets processes running from `memfd` file descriptors, representing a form of fileless execution. The **Running from Temp Directory** heuristic flags processes executing from temporary directories such as `/tmp`, `/var/tmp`, or `/dev/shm`, which are frequently used by malware for payload storage and execution.

The **World-Writable Executable** check identifies processes whose executable files are world-writable, allowing any system user to modify them. **W+X Memory Regions** detection finds processes with memory regions that are both writable and executable, a common characteristic of shellcode and in-memory threats. The **Empty Command Line** heuristic detects processes with empty command lines, potentially indicating process tampering. Similarly, **Short Command Line** detection flags processes with very short command lines that may be used to hide malicious activity.

The **Obfuscated Command Line** heuristic identifies command lines containing "base64", suggesting possible obfuscation. **Code Execution in Command Line** detection flags command lines containing "eval" or "exec", indicating potential code execution from the command line. The **Name/Argv Mismatch** check identifies discrepancies between the process name and the first command-line argument (`argv[0]`), a sign of process masquerading.

The **Unusual Parent Process** heuristic detects processes with atypical parent processes, such as `bash` running as a child of `apache2`. **LD_PRELOAD/LD_LIBRARY_PATH** detection identifies processes with these environment variables set, which can be exploited to load malicious libraries. The **Ptraced** heuristic flags processes being traced by another process using `ptrace`, which can indicate debugging or malicious code injection.

The **High CPU Usage** check identifies processes consuming excessive CPU resources, potentially indicating malicious activity like cryptomining. **Running without a TTY** detection flags shells or interpreters (like `bash` or `python`) running without terminals, possible indicators of reverse shells. The **Outbound to Watched Port** heuristic detects processes with outbound network connections to ports on a configurable watch list. **Many Outbound Connections** identifies processes with unusually large numbers of outbound network connections. Finally, the **No Executable Path** heuristic flags processes lacking an executable path, which while common for kernel threads, can also indicate malicious processes.

### 4.2 Machine Learning-based Detection

When a trained model is available, `procwatch` calculates an anomaly score for each process based on extracted features. These features include CPU usage, memory usage, number of threads, number of open file descriptors, number of network connections, and additional process characteristics. The anomaly score is then multiplied by a configurable weight and added to the heuristic score to produce the total risk score.

### 4.3 Response Actions

When a suspicious process is detected, `procwatch` can execute several response actions. The **Alert** action prints a detailed alert message to the console. The **Kill** action terminates the process using `SIGKILL`. The **Dump** action creates forensic artifacts of the process in a specified directory for later analysis. The **Stop** action halts the scan immediately after the first alert is generated.

---

## 5. Implementation

Procwatch is implemented as a command-line tool with two main subcommands: `scan` and `train`.

### 5.1 Scan Command

The `scan` command performs system-wide process monitoring to detect suspicious activities. The command accepts the following parameters:

```bash
procwatch scan [OPTIONS]
```

The `--interval <SECONDS>` parameter enables continuous scanning at specified intervals; without this parameter, a single scan is performed. The `--config <PATH>` option specifies a custom YAML configuration file path. The `--model <PATH>` parameter provides the path to a trained machine learning model. The `--min-score <FLOAT>` option overrides the minimum score threshold from the configuration file. The `--stop-on-alert` flag causes the scan to terminate after detecting the first suspicious process. The `--kill-on-alert` flag enables automatic termination of suspicious processes. The `--dump <DIRECTORY>` parameter specifies a directory for storing forensic artifacts of suspicious processes.

Example usage scenarios include running a single scan with the default configuration, executing continuous scans at 10-second intervals, automatically killing suspicious processes upon detection, and dumping artifacts to `/tmp/procwatch_dumps` for forensic analysis.

### 5.2 Train Command

The `train` command creates a baseline model for machine learning-based anomaly detection.

```bash
procwatch train [OPTIONS]
```

The `--duration <SECONDS>` parameter sets the training duration (default: 60 seconds). The `--interval <SECONDS>` option specifies the sampling interval during training (default: 5.0 seconds). The `--config <PATH>` parameter provides a custom YAML configuration file path. The `--model <PATH>` option specifies where to save the trained model (default: `~/.local/share/procwatch/model.json`).

A typical training session involves collecting process feature data for a specified duration, such as 120 seconds, to establish a baseline of normal system behavior.

---

## 6. Configuration

Procwatch uses a YAML-based configuration system. By default, the tool searches for `~/.procwatch.yaml`, though alternative paths can be specified using the `--config` option.

The default configuration includes the following parameters:

```yaml
min_score: 2
cpu_high: 90.0
ports: "3333,4444,5555,6666,7777,14444,33333"
topk: 20
ml_weight: 2.0
use_sklearn: false
weights:
    deleted_exe: 4
    memfd_exe: 4
    tmp_exe: 3
    world_writable_exe: 2
    wx_mem: 3
    empty_cmdline: 1
    short_cmdline: 1
    obfuscated_cmdline: 2
    code_exec_cmdline: 1
    name_argv_mismatch: 1
    unusual_parent: 3
    ld_preload: 2
    ptraced: 3
    high_cpu: 1
    no_tty: 3
    watched_port: 2
    many_conns: 1
    no_exe: 1
whitelist:
    names: ["systemd", "kthreadd", "kworker", "sshd", "cron", "bash", "NetworkManager", "journald"]
    users: ["root"]
    patterns: ["/usr/*", "/bin/*", "/sbin/*", "(sd-pam)", "kworker*", "ksoftirqd*", "rcu*", "migration*", "idle_inject*", "cpuhp*", "pool_workqueue_release*", "systemd-userwor*", "dbus-broker-lau*", "systemd-timesyn*", "systemd-resolve*", "systemd-journal*"]
    hashes: []
    paths: []
```

The `min_score` parameter defines the minimum total score threshold for classifying a process as suspicious. The `cpu_high` setting specifies the CPU usage percentage threshold for the high CPU usage heuristic. The `ports` parameter contains a comma-separated list of network ports monitored for outbound connections. The `topk` value limits the maximum number of findings reported in a single scan. The `ml_weight` parameter determines the weight applied to machine learning anomaly scores. The `use_sklearn` flag controls whether to use the `IsolationForestModel` from `scikit-learn` (when true) or the simpler `ZScoreModel` (when false) for training. The `weights` dictionary assigns importance values to each heuristic. The `whitelist` configuration defines rules for exempting trusted processes, users, paths, and executable hashes from detection.

### 6.1 Forensic Artifact Collection

When the `--dump` option is enabled, `procwatch` creates a dedicated directory for each detected suspicious process. Each directory is named using the pattern `<PID>_<TIMESTAMP>` and contains multiple forensic artifacts. The `cmdline` file stores the process's command line arguments. The `environ` file captures the process's environment variables. The `exe` file contains a copy of the process's executable binary. If executable copying fails, an `exe.error` file documents the error message. The `maps` file records the process's memory map structure. The `fds` file lists the process's open file descriptors. These collected artifacts enable comprehensive forensic investigation and post-incident analysis.
