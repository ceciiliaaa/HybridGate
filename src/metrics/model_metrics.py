"""
Model Performance Metrics for HybridGate Framework

Computes standard ML metrics for secret detection models:
- Confusion matrix (TP, FP, TN, FN)
- Precision, Recall, F1 Score
- Location accuracy
"""

from typing import Dict, List, Any, Tuple
from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    """Confusion matrix for binary classification."""
    tp: int = 0  # True Positives: secret exists, predicted secret
    fp: int = 0  # False Positives: no secret, predicted secret
    tn: int = 0  # True Negatives: no secret, predicted no secret
    fn: int = 0  # False Negatives: secret exists, predicted no secret

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def actual_positives(self) -> int:
        return self.tp + self.fn

    @property
    def actual_negatives(self) -> int:
        return self.fp + self.tn

    @property
    def predicted_positives(self) -> int:
        return self.tp + self.fp

    @property
    def predicted_negatives(self) -> int:
        return self.tn + self.fn

    def to_dict(self) -> Dict[str, int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total
        }


def compute_confusion_matrix(
    results: List[Dict[str, Any]],
    pred_key: str = "pred_has_secret",
    gt_key: str = "gt_has_secret"
) -> ConfusionMatrix:
    """
    Compute confusion matrix from evaluation results.

    Args:
        results: List of result dictionaries
        pred_key: Key for prediction field
        gt_key: Key for ground truth field

    Returns:
        ConfusionMatrix instance
    """
    cm = ConfusionMatrix()

    for r in results:
        gt = r.get(gt_key, False)
        pred = r.get(pred_key, False)

        if gt and pred:
            cm.tp += 1
        elif gt and not pred:
            cm.fn += 1
        elif not gt and pred:
            cm.fp += 1
        else:
            cm.tn += 1

    return cm


def compute_precision_recall_f1(cm: ConfusionMatrix) -> Dict[str, float]:
    """
    Compute precision, recall, and F1 score from confusion matrix.

    Args:
        cm: ConfusionMatrix instance

    Returns:
        Dictionary with precision, recall, f1, and accuracy
    """
    # Precision = TP / (TP + FP)
    precision = cm.tp / (cm.tp + cm.fp) if (cm.tp + cm.fp) > 0 else 0.0

    # Recall = TP / (TP + FN)
    recall = cm.tp / (cm.tp + cm.fn) if (cm.tp + cm.fn) > 0 else 0.0

    # F1 = 2 * (P * R) / (P + R)
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Accuracy = (TP + TN) / Total
    accuracy = (cm.tp + cm.tn) / cm.total if cm.total > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4)
    }


def compute_location_accuracy(
    results: List[Dict[str, Any]],
    pred_line_key: str = "pred_location_line",
    gt_line_key: str = "gt_line_start"
) -> Dict[str, Any]:
    """
    Compute location prediction accuracy.

    Only considers samples where:
    - Ground truth has a secret
    - Model correctly predicted a secret

    Args:
        results: List of result dictionaries
        pred_line_key: Key for predicted line number
        gt_line_key: Key for ground truth line number

    Returns:
        Dictionary with location accuracy metrics
    """
    true_positives = [
        r for r in results
        if r.get("gt_has_secret") and r.get("pred_has_secret")
    ]

    if not true_positives:
        return {
            "location_accuracy": 0.0,
            "location_hits": 0,
            "total_true_positives": 0
        }

    location_hits = 0
    for r in true_positives:
        pred_line = r.get(pred_line_key)
        gt_line = r.get(gt_line_key)

        if pred_line is not None and gt_line is not None:
            if int(pred_line) == int(gt_line):
                location_hits += 1

    accuracy = location_hits / len(true_positives)

    return {
        "location_accuracy": round(accuracy, 4),
        "location_hits": location_hits,
        "total_true_positives": len(true_positives)
    }


def compute_model_metrics(
    results: List[Dict[str, Any]],
    detector_name: str = "llm",
    pred_key: str = "pred_has_secret",
    pred_line_key: str = "pred_location_line"
) -> Dict[str, Any]:
    """
    Compute all model metrics for a detector.

    Args:
        results: List of result dictionaries
        detector_name: Name of the detector for labeling
        pred_key: Key for prediction field
        pred_line_key: Key for predicted line number

    Returns:
        Comprehensive metrics dictionary
    """
    cm = compute_confusion_matrix(results, pred_key=pred_key)
    prf = compute_precision_recall_f1(cm)
    loc = compute_location_accuracy(results, pred_line_key=pred_line_key)

    return {
        "detector": detector_name,
        "confusion_matrix": cm.to_dict(),
        **prf,
        **loc
    }


def compute_metrics_by_condition(
    results: List[Dict[str, Any]],
    pred_key: str = "pred_has_secret"
) -> Dict[str, Dict[str, Any]]:
    """
    Compute metrics grouped by experimental condition.

    Args:
        results: List of result dictionaries
        pred_key: Key for prediction field

    Returns:
        Dictionary mapping condition -> metrics
    """
    # Group by condition
    by_condition: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        condition = r.get("condition", "unknown")
        if condition not in by_condition:
            by_condition[condition] = []
        by_condition[condition].append(r)

    # Compute metrics per condition
    metrics_by_condition = {}
    for condition, cond_results in sorted(by_condition.items()):
        cm = compute_confusion_matrix(cond_results, pred_key=pred_key)
        prf = compute_precision_recall_f1(cm)

        metrics_by_condition[condition] = {
            "count": len(cond_results),
            "confusion_matrix": cm.to_dict(),
            **prf
        }

    return metrics_by_condition


def compute_metrics_by_secret_type(
    results: List[Dict[str, Any]],
    pred_key: str = "pred_has_secret"
) -> Dict[str, Dict[str, Any]]:
    """
    Compute metrics grouped by secret type.

    Args:
        results: List of result dictionaries
        pred_key: Key for prediction field

    Returns:
        Dictionary mapping secret_type -> metrics
    """
    # Group by secret type
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        secret_type = r.get("gt_secret_type", "none")
        if secret_type not in by_type:
            by_type[secret_type] = []
        by_type[secret_type].append(r)

    # Compute metrics per type
    metrics_by_type = {}
    for secret_type, type_results in sorted(by_type.items()):
        cm = compute_confusion_matrix(type_results, pred_key=pred_key)
        prf = compute_precision_recall_f1(cm)

        metrics_by_type[secret_type] = {
            "count": len(type_results),
            "confusion_matrix": cm.to_dict(),
            **prf
        }

    return metrics_by_type
