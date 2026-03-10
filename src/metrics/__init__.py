"""
Metrics Module for HybridGate Framework

Provides comprehensive metrics calculation for evaluating:
- Model performance (Precision, Recall, F1)
- Gate effectiveness (Leak-Escape-Rate, False-Block-Rate)
- Statistical significance (McNemar Test)
"""

from .model_metrics import (
    compute_confusion_matrix,
    compute_precision_recall_f1,
    compute_location_accuracy,
    compute_model_metrics
)
from .gate_metrics import (
    compute_leak_escape_rate,
    compute_false_block_rate,
    compute_review_load,
    compute_gate_metrics
)
from .statistical_tests import (
    run_mcnemar_test,
    compute_contingency_table,
    interpret_mcnemar_result
)

__all__ = [
    # Model metrics
    'compute_confusion_matrix',
    'compute_precision_recall_f1',
    'compute_location_accuracy',
    'compute_model_metrics',
    # Gate metrics
    'compute_leak_escape_rate',
    'compute_false_block_rate',
    'compute_review_load',
    'compute_gate_metrics',
    # Statistical tests
    'run_mcnemar_test',
    'compute_contingency_table',
    'interpret_mcnemar_result',
]
