"""
Synthetic evaluation framework for AEGIS adaptive anomaly detection.

Anomaly detection is unsupervised, so effectiveness is measured against
generated ground truth: the simulator replays realistic normal API traffic
while injecting labeled attack scenarios, then reports precision, recall,
false-positive rate, and detection latency.

Run:  python -m simulator.evaluate
"""
