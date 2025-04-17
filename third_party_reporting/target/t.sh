#!/bin/bash

# Run Benchmarks
cargo bench

# Make Running Time Table
python3 script.py

# Make Plots
python3 plots.py
