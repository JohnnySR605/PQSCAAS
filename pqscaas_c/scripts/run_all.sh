#!/usr/bin/env bash
# Run all active experiments and save results to results/
set -e

cd "$(dirname "$0")/.."

if [ ! -f pqscaas_app ] || [ ! -f enclave.signed.so ]; then
    echo "App not built. Running build first..."
    bash scripts/build.sh
fi

mkdir -p results figures

echo "======================================================================"
echo "Running all experiments (1-11)..."
echo "======================================================================"

t0=$(date +%s)
./pqscaas_app all
t1=$(date +%s)

echo
echo "======================================================================"
echo "All experiments done in $((t1 - t0))s"
echo "CSV results in: results/"
echo "Generate figures:  cd plot_scripts && python plot_all.py"
echo "======================================================================"
