#!/usr/bin/env python3
"""
Generate all PQSCAAS figures from CSV results (v4, figures 1-11).

Reads:  ../results/*.csv
Writes: ../figures/*.png

Figures (Fig N produced by Exp N):
  Fig 1  KeyGen scaling (exp1)
  Fig 2  Phase 4 vs file size (exp2)
  Fig 3  Batch signcrypt vs N_requests (exp3)
  Fig 4  Phase 5 vs file size (exp4)
  Fig 5  Sequential unsigncrypt vs N (exp5)
  Fig 6  Signcrypt throughput vs workload (exp6)
  Fig 7  Unsigncrypt throughput vs workload (exp7)
    Fig 8  Throughput vs request rate, dynamic elastic (exp8)
    Fig 9  Active enclaves vs request rate (exp9)
    Fig 10 Merkle vs CRL revocation (exp10)
    Fig 11 Policy update — deferred binding vs naive re-encryption (exp11)
"""

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
FIGURES_DIR = os.path.join(os.path.dirname(__file__), '..', 'figures')
os.makedirs(FIGURES_DIR, exist_ok=True)

# Consistent palette
COLORS = {
    'PQSCAAS':         '#1f77b4',
    'PQSCAAS_NT':      '#17becf',
    'PQSCAAS_WT':      '#1f77b4',
    'Sinha2026':       '#d62728',
    'Yu2021':          '#2ca02c',
    'Bai2025':         '#ff7f0e',
    'Yu2021_naive':    '#2ca02c',
    'Bai2025_naive':   '#ff7f0e',
    'Sinha2026_naive': '#d62728',
    'Merkle':          '#1f77b4',
    'CRL':             '#d62728',
}

def fmt_axes(ax):
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

def _csv(name):
    return os.path.join(RESULTS_DIR, name)

def _save(name):
    path = os.path.join(FIGURES_DIR, name)
    plt.tight_layout()
    plt.savefig(path, dpi=140)
    plt.close()
    print(f"✓ {name}")

# -------------------------------------------------------------------------
# Fig 1: KeyGen scaling
# -------------------------------------------------------------------------
def plot_fig1():
    df = pd.read_csv(_csv('exp1_keygen_vs_users.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['n_users']
    for s, lbl in [('PQSCAAS',   'PQSCAAS'),
                   ('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='o', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Number of users')
    ax.set_ylabel('Total KeyGen time (ms)')
    ax.set_title('Fig. 1: Key Generation Time vs Number of Users')
    ax.legend()
    fmt_axes(ax)
    _save('fig1_keygen_vs_users.png')

# -------------------------------------------------------------------------
# Fig 2: Phase 4 vs file size (was exp1 in v3)
# -------------------------------------------------------------------------
def plot_fig2():
    df = pd.read_csv(_csv('exp2_phase4_vs_filesize.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['file_size_bytes'] / 1024.0
    for s, lbl in [('PQSCAAS',   'PQSCAAS'),
                   ('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='o', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('File size (KB)')
    ax.set_ylabel('Signcryption cost (ms)')
    ax.set_title('Fig. 2: Signcryption Cost vs File Size')
    ax.legend()
    fmt_axes(ax)
    _save('fig2_phase4_vs_filesize.png')

# -------------------------------------------------------------------------
# Fig 3: Batch signcrypt vs N_requests (was exp2)
# -------------------------------------------------------------------------
def plot_fig3():
    df = pd.read_csv(_csv('exp3_signcrypt_batch_vs_requests.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['n_requests']
    ax.errorbar(x, df['PQSCAAS_no_timeout_mean'],   yerr=df['PQSCAAS_no_timeout_std'],
                marker='o', capsize=3, label='PQSCAAS (no timeout)',
                color=COLORS['PQSCAAS_NT'], linewidth=1.8)
    ax.errorbar(x, df['PQSCAAS_with_timeout_mean'], yerr=df['PQSCAAS_with_timeout_std'],
                marker='s', capsize=3, label='PQSCAAS (with timeout)',
                color=COLORS['PQSCAAS_WT'], linewidth=1.8)
    for s, lbl in [('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='^', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Number of requests')
    ax.set_ylabel('Total signcryption time (ms)')
    ax.set_title('Fig. 3: Batch Signcryption vs Number of Requests')
    ax.legend()
    fmt_axes(ax)
    _save('fig3_signcrypt_batch_vs_requests.png')

# -------------------------------------------------------------------------
# Fig 4: Phase 5 vs file size (was exp3)
# -------------------------------------------------------------------------
def plot_fig4():
    df = pd.read_csv(_csv('exp4_phase5_vs_filesize.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['file_size_bytes'] / 1024.0
    for s, lbl in [('PQSCAAS',   'PQSCAAS'),
                   ('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='o', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('File size (KB)')
    ax.set_ylabel('Unsigncryption cost (ms)')
    ax.set_title('Fig. 4: Unsigncryption Cost vs File Size')
    ax.legend()
    fmt_axes(ax)
    _save('fig4_phase5_vs_filesize.png')

# -------------------------------------------------------------------------
# Fig 5: Sequential unsigncrypt vs N (was exp4)
# -------------------------------------------------------------------------
def plot_fig5():
    df = pd.read_csv(_csv('exp5_unsigncrypt_vs_requests.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['n_requests']
    for s, lbl in [('PQSCAAS',   'PQSCAAS'),
                   ('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='o', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Number of requests')
    ax.set_ylabel('Total unsigncryption time (ms)')
    ax.set_title('Fig. 5: Sequential Unsigncryption vs Number of Requests')
    ax.legend()
    fmt_axes(ax)
    _save('fig5_unsigncrypt_vs_requests.png')

# -------------------------------------------------------------------------
# Fig 6: Signcrypt throughput vs workload (was exp5)
# -------------------------------------------------------------------------
def plot_fig6():
    df = pd.read_csv(_csv('exp6_signcrypt_throughput.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['workload']
    ax.errorbar(x, df['PQSCAAS_no_timeout_mean'],   yerr=df['PQSCAAS_no_timeout_std'],
                marker='o', capsize=3, label='PQSCAAS (no timeout)',
                color=COLORS['PQSCAAS_NT'], linewidth=1.8)
    ax.errorbar(x, df['PQSCAAS_with_timeout_mean'], yerr=df['PQSCAAS_with_timeout_std'],
                marker='s', capsize=3, label='PQSCAAS (with timeout)',
                color=COLORS['PQSCAAS_WT'], linewidth=1.8)
    for s, lbl in [('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='^', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Concurrent workload')
    ax.set_ylabel('Signcryption throughput (req/s)')
    ax.set_title('Fig. 6: Signcryption Throughput vs Workload')
    ax.legend()
    fmt_axes(ax)
    _save('fig6_signcrypt_throughput.png')

# -------------------------------------------------------------------------
# Fig 7: Unsigncrypt throughput vs workload (was exp6)
# -------------------------------------------------------------------------
def plot_fig7():
    df = pd.read_csv(_csv('exp7_unsigncrypt_throughput.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['workload']
    for s, lbl in [('PQSCAAS',   'PQSCAAS'),
                   ('Sinha2026', 'Sinha 2026'),
                   ('Yu2021',    'Yu 2021'),
                   ('Bai2025',   'Bai 2025')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker='o', capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log')
    ax.set_xlabel('Concurrent workload')
    ax.set_ylabel('Unsigncryption throughput (req/s)')
    ax.set_title('Fig. 7: Unsigncryption Throughput vs Workload')
    ax.legend()
    fmt_axes(ax)
    _save('fig7_unsigncrypt_throughput.png')

# Fig 8: Throughput vs request rate (exp8)
# -------------------------------------------------------------------------
def plot_fig8():
    df = pd.read_csv(_csv('exp8_throughput_vs_rate.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['request_rate']
    for s, lbl, marker in [('PQSCAAS',   'PQSCAAS (dynamic elastic)', 'o'),
                           ('Bai2025',   'Bai 2025 (single)',         '^'),
                           ('Yu2021',    'Yu 2021 (single)',          's'),
                           ('Sinha2026', 'Sinha 2026 (single)',       'D')]:
        ax.errorbar(x, df[f'{s}_mean'], yerr=df[f'{s}_std'],
                    marker=marker, capsize=3, label=lbl,
                    color=COLORS[s], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Request Rate (req/s)')
    ax.set_ylabel('Achieved throughput (req/s)')
    ax.set_title('Fig. 8: Throughput vs Request Rate (Dynamic Elastic)')
    ax.legend()
    fmt_axes(ax)
    _save('fig8_throughput_vs_rate.png')

# -------------------------------------------------------------------------
# Fig 9: Active enclaves vs request rate (exp9)
# -------------------------------------------------------------------------
def plot_fig9():
    df = pd.read_csv(_csv('exp9_active_enclaves_vs_rate.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['request_rate']
    ax.errorbar(x, df['active_enclaves_mean'], yerr=df['active_enclaves_std'],
                marker='o', capsize=3, label='Active enclaves',
                color=COLORS['PQSCAAS'], linewidth=1.8, drawstyle='steps-post')
    ax.set_xscale('log')
    ax.set_xlabel('Request Rate (req/s)')
    ax.set_ylabel('Number of active enclaves')
    ax.set_title('Fig. 9: Active Enclaves vs Request Rate')
    ax.legend(loc='upper left')
    fmt_axes(ax)
    _save('fig9_active_enclaves_vs_rate.png')

# -------------------------------------------------------------------------
# Fig 10: Merkle vs CRL revocation (single plot - verification time only)
# -------------------------------------------------------------------------
def plot_fig10():
    df = pd.read_csv(_csv('exp10_merkle_vs_crl.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['n_revoked']

    ax.errorbar(x, df['Merkle_time_ms_mean'], yerr=df['Merkle_time_ms_std'],
                marker='o', capsize=3, label='PQSCAAS (Merkle root)',
                color=COLORS['Merkle'], linewidth=1.8)
    ax.errorbar(x, df['CRL_time_ms_mean'], yerr=df['CRL_time_ms_std'],
                marker='s', capsize=3, label='Linear CRL',
                color=COLORS['CRL'], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Number of revoked users')
    ax.set_ylabel('Revocation verification time (ms)')
    ax.set_title('Fig. 10: Merkle Root vs CRL Revocation')
    ax.legend()
    fmt_axes(ax)
    _save('fig10_merkle_vs_crl.png')

# -------------------------------------------------------------------------
# Fig 11: Policy update — deferred binding vs naive re-encryption (exp11)
# -------------------------------------------------------------------------
def plot_fig11():
    df = pd.read_csv(_csv('exp11_policy_update.csv'))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = df['n_records']
    ax.errorbar(x, df['PQSCAAS_mean'], yerr=df['PQSCAAS_std'],
                marker='o', capsize=3, label='PQSCAAS (deferred binding)',
                color=COLORS['PQSCAAS'], linewidth=1.8)
    ax.errorbar(x, df['Bai2025_naive_mean'], yerr=df['Bai2025_naive_std'],
                marker='^', capsize=3, label='Bai 2025 (naive re-encrypt)',
                color=COLORS['Bai2025'], linewidth=1.8)
    ax.errorbar(x, df['Yu2021_naive_mean'], yerr=df['Yu2021_naive_std'],
                marker='s', capsize=3, label='Yu 2021 (naive re-encrypt)',
                color=COLORS['Yu2021'], linewidth=1.8)
    ax.errorbar(x, df['Sinha2026_naive_mean'], yerr=df['Sinha2026_naive_std'],
                marker='D', capsize=3, label='Sinha 2026 (naive re-encrypt)',
                color=COLORS['Sinha2026'], linewidth=1.8)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Number of affected records')
    ax.set_ylabel('Total policy-update time (ms)')
    ax.set_title('Fig. 11: Policy Update — Deferred Binding vs Naive Re-encryption')
    ax.legend()
    fmt_axes(ax)
    _save('fig11_policy_update.png')

# -------------------------------------------------------------------------
def main():
    print(f"Reading CSVs from: {RESULTS_DIR}")
    print(f"Writing figures to: {FIGURES_DIR}\n")
    plotters = [
        ('fig1',  plot_fig1),
        ('fig2',  plot_fig2),
        ('fig3',  plot_fig3),
        ('fig4',  plot_fig4),
        ('fig5',  plot_fig5),
        ('fig6',  plot_fig6),
        ('fig7',  plot_fig7),
        ('fig8',  plot_fig8),
        ('fig9',  plot_fig9),
        ('fig10', plot_fig10),
        ('fig11', plot_fig11),
    ]
    for name, fn in plotters:
        try:
            fn()
        except Exception as e:
            print(f"  ✗ {name}: {e}")
    print(f"\nDone. Figures saved to: {FIGURES_DIR}")

if __name__ == '__main__':
    main()
