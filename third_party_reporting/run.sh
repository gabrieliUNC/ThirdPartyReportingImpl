#!/bin/bash

cargo clean

echo "\n\nBuilding All Packages!\n\n"
cargo build

echo "\n\nRunning All schemes and reporting Communication Costs!\n\n"
cargo run -- --num-moderators 1 --msg-size 100 --test-e2ee --basic --mod-priv --const-priv

echo "\n\nRunning Computation Time Benchmarks!\n\n"
cargo bench

echo "\n\nCollecting Data into Computation Time Table!\n\n"
python3 script.py

echo "\n\nPlotting Data!\n\n"
python3 plots.py
