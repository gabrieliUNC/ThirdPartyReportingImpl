#!/bin/bash

#cargo clean

#echo "\n\nBuilding All Packages!\n\n"
#cargo build

#echo "\n\nRunning Computation Time Benchmarks!\n\n"
#cargo bench

echo "\n\nCollecting Data into Computation Time Table!\n\n"
python3 script.py

echo "\n\nPlotting Data!\n\n"
python3 plots.py

echo "\n\nRunning All schemes and reporting Communication Costs!\n\n"
cargo run -- --num-moderators 1 --msg-size 100 --test-e2ee --basic --const-priv

# Run Additional communication cost tests for Mod Priv-1

for ((i = 1; i <= 11; ++i)); do
	cargo run -- --num-moderators $i --mod-priv
done
