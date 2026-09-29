"""Randomized evaluation of the detection engine (Phase 10).

The five bundled sample scenarios are fixed templates, so passing them proves the engine
handles *those* inputs - not that it generalizes. This package generates many randomized
variations of each scenario, embedded in realistic background activity, and measures
detection rate, classification accuracy, and false alarms against known ground truth.
"""
