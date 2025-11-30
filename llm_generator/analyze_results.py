#!/usr/bin/env python3
"""
Analyze LLM classification results.

Generate summary statistics, confusion matrix, and performance metrics
segmented by attack type.

Usage:
    python analyze_results.py [model_name]

Examples:
    python analyze_results.py mistral
    python analyze_results.py gemma
    python analyze_results.py llama
    python analyze_results.py qwen
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import numpy as np
import sys


def load_data(file_path: str):
    """Load the labeled dataset."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return pd.DataFrame(data)


def convert_labels(df):
    """Convert label strings to integers for analysis."""
    # Convert 'malicious'/'benign' to 1/0 if needed
    df['true_label'] = df['label'].apply(lambda x: 1 if x == 'malicious' else 0)

    # Convert predicted labels to int (handle None)
    df['predicted_label'] = df['predicted_llm_response'].apply(
        lambda x: int(x) if x is not None else None
    )

    return df


def calculate_metrics(tp, fp, tn, fn):
    """Calculate classification metrics."""
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0  # Also called TPR
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    # False Positive Rate
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # False Negative Rate
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'tpr': recall,  # Same as recall
        'fpr': fpr,
        'fnr': fnr
    }


def analyze_overall(df):
    """Generate overall statistics."""
    print("="*70)
    print("OVERALL STATISTICS")
    print("="*70)

    # Filter out entries without predictions
    df_valid = df[df['predicted_label'].notna()].copy()

    print(f"\nTotal entries: {len(df)}")
    print(f"Valid predictions: {len(df_valid)}")
    print(f"Missing predictions: {len(df) - len(df_valid)}")

    # True label distribution
    print("\n" + "-"*70)
    print("TRUE LABEL DISTRIBUTION")
    print("-"*70)
    label_counts = df['true_label'].value_counts()
    print(f"Benign (0): {label_counts.get(0, 0)} ({label_counts.get(0, 0)/len(df)*100:.1f}%)")
    print(f"Malicious (1): {label_counts.get(1, 0)} ({label_counts.get(1, 0)/len(df)*100:.1f}%)")

    # Confusion matrix
    print("\n" + "-"*70)
    print("CONFUSION MATRIX (Valid Predictions Only)")
    print("-"*70)

    tp = len(df_valid[(df_valid['true_label'] == 1) & (df_valid['predicted_label'] == 1)])
    fp = len(df_valid[(df_valid['true_label'] == 0) & (df_valid['predicted_label'] == 1)])
    tn = len(df_valid[(df_valid['true_label'] == 0) & (df_valid['predicted_label'] == 0)])
    fn = len(df_valid[(df_valid['true_label'] == 1) & (df_valid['predicted_label'] == 0)])

    print(f"\n                Predicted")
    print(f"                0        1")
    print(f"Actual  0     {tn:5}   {fp:5}   (TN={tn}, FP={fp})")
    print(f"        1     {fn:5}   {tp:5}   (FN={fn}, TP={tp})")

    # Metrics
    metrics = calculate_metrics(tp, fp, tn, fn)

    print("\n" + "-"*70)
    print("PERFORMANCE METRICS")
    print("-"*70)
    print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"Recall (TPR): {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"F1 Score:  {metrics['f1_score']:.4f}")
    print(f"\nTrue Positive Rate (TPR):  {metrics['tpr']:.4f} ({metrics['tpr']*100:.2f}%)")
    print(f"False Positive Rate (FPR): {metrics['fpr']:.4f} ({metrics['fpr']*100:.2f}%)")
    print(f"False Negative Rate (FNR): {metrics['fnr']:.4f} ({metrics['fnr']*100:.2f}%)")

    return metrics


def analyze_by_type(df):
    """Analyze performance by attack/query type."""
    print("\n\n" + "="*70)
    print("PERFORMANCE BY TYPE")
    print("="*70)

    # Filter valid predictions
    df_valid = df[df['predicted_label'].notna()].copy()

    # Get unique types
    types = sorted(df_valid['type'].unique())

    results = []

    for qtype in types:
        df_type = df_valid[df_valid['type'] == qtype]

        if len(df_type) == 0:
            continue

        tp = len(df_type[(df_type['true_label'] == 1) & (df_type['predicted_label'] == 1)])
        fp = len(df_type[(df_type['true_label'] == 0) & (df_type['predicted_label'] == 1)])
        tn = len(df_type[(df_type['true_label'] == 0) & (df_type['predicted_label'] == 0)])
        fn = len(df_type[(df_type['true_label'] == 1) & (df_type['predicted_label'] == 0)])

        metrics = calculate_metrics(tp, fp, tn, fn)

        results.append({
            'type': qtype,
            'total': len(df_type),
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1': metrics['f1_score'],
            'tpr': metrics['tpr'],
            'fpr': metrics['fpr'],
            'fnr': metrics['fnr']
        })

    # Display results
    results_df = pd.DataFrame(results)

    print("\n" + "-"*70)
    print("Summary Table")
    print("-"*70)
    print(results_df[['type', 'total', 'accuracy', 'precision', 'recall', 'f1']].to_string(index=False))

    print("\n" + "-"*70)
    print("Error Rates by Type")
    print("-"*70)
    print(results_df[['type', 'tpr', 'fpr', 'fnr']].to_string(index=False))

    print("\n" + "-"*70)
    print("Confusion Matrix Counts by Type")
    print("-"*70)
    print(results_df[['type', 'tp', 'fp', 'tn', 'fn']].to_string(index=False))

    return results_df


def create_plots(df, overall_metrics, type_metrics, output_dir):
    """Create comprehensive visualization plots."""
    import os
    os.makedirs(output_dir, exist_ok=True)

    # Set style
    sns.set_style("whitegrid")
    plt.rcParams['figure.figsize'] = (12, 8)

    df_valid = df[df['predicted_label'].notna()].copy()

    # Plot 1: Confusion Matrix Heatmap
    print("\nGenerating confusion matrix heatmap...")
    fig, ax = plt.subplots(figsize=(8, 6))

    tp = len(df_valid[(df_valid['true_label'] == 1) & (df_valid['predicted_label'] == 1)])
    fp = len(df_valid[(df_valid['true_label'] == 0) & (df_valid['predicted_label'] == 1)])
    tn = len(df_valid[(df_valid['true_label'] == 0) & (df_valid['predicted_label'] == 0)])
    fn = len(df_valid[(df_valid['true_label'] == 1) & (df_valid['predicted_label'] == 0)])

    cm = np.array([[tn, fp], [fn, tp]])
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign (0)', 'Malicious (1)'],
                yticklabels=['Benign (0)', 'Malicious (1)'],
                ax=ax, cbar_kws={'label': 'Count'})
    ax.set_xlabel('Predicted Label', fontsize=12)
    ax.set_ylabel('True Label', fontsize=12)
    ax.set_title('Confusion Matrix - Overall Performance', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(f'{output_dir}/confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()

    # Plot 2: Performance Metrics by Type
    print("Generating performance metrics by type...")
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1']
    titles = ['Accuracy by Type', 'Precision by Type', 'Recall (TPR) by Type', 'F1 Score by Type']

    for idx, (metric, title) in enumerate(zip(metrics_to_plot, titles)):
        ax = axes[idx // 2, idx % 2]
        data = type_metrics.sort_values(metric, ascending=True)

        bars = ax.barh(data['type'], data[metric], color=plt.cm.viridis(data[metric]))
        ax.set_xlabel(metric.capitalize(), fontsize=11)
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.set_xlim(0, 1)

        # Add value labels
        for i, (bar, val) in enumerate(zip(bars, data[metric])):
            ax.text(val + 0.02, i, f'{val:.3f}', va='center', fontsize=9)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/metrics_by_type.png', dpi=300, bbox_inches='tight')
    plt.close()

    # Plot 3: Error Rates (FPR, FNR) by Type
    print("Generating error rates by type...")
    fig, ax = plt.subplots(figsize=(14, 8))

    x = np.arange(len(type_metrics))
    width = 0.35

    bars1 = ax.bar(x - width/2, type_metrics['fpr'], width, label='False Positive Rate', color='salmon')
    bars2 = ax.bar(x + width/2, type_metrics['fnr'], width, label='False Negative Rate', color='lightblue')

    ax.set_xlabel('Query Type', fontsize=12)
    ax.set_ylabel('Error Rate', fontsize=12)
    ax.set_title('False Positive Rate vs False Negative Rate by Type', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(type_metrics['type'], rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/error_rates_by_type.png', dpi=300, bbox_inches='tight')
    plt.close()

    # Plot 4: Distribution of True Labels
    print("Generating label distribution...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Pie chart
    label_counts = df['true_label'].value_counts()
    colors = ['#66b3ff', '#ff9999']
    ax1.pie(label_counts, labels=['Benign (0)', 'Malicious (1)'], autopct='%1.1f%%',
            colors=colors, startangle=90)
    ax1.set_title('Overall Label Distribution', fontsize=12, fontweight='bold')

    # Bar chart by type
    label_by_type = df.groupby(['type', 'true_label']).size().unstack(fill_value=0)
    label_by_type.plot(kind='bar', stacked=True, ax=ax2, color=colors)
    ax2.set_xlabel('Query Type', fontsize=11)
    ax2.set_ylabel('Count', fontsize=11)
    ax2.set_title('Label Distribution by Type', fontsize=12, fontweight='bold')
    ax2.legend(['Benign', 'Malicious'])
    ax2.set_xticklabels(ax2.get_xticklabels(), rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(f'{output_dir}/label_distribution.png', dpi=300, bbox_inches='tight')
    plt.close()

    # Plot 5: Overall Performance Metrics Bar Chart
    print("Generating overall performance metrics...")
    fig, ax = plt.subplots(figsize=(10, 6))

    metrics = ['accuracy', 'precision', 'recall', 'f1_score']
    values = [overall_metrics[m] for m in metrics]
    labels = ['Accuracy', 'Precision', 'Recall', 'F1 Score']

    bars = ax.bar(labels, values, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Overall Classification Performance', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 1)
    ax.grid(axis='y', alpha=0.3)

    # Add value labels
    for bar, val in zip(bars, values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                f'{val:.3f}', ha='center', va='bottom', fontsize=11, fontweight='bold')

    plt.tight_layout()
    plt.savefig(f'{output_dir}/overall_performance.png', dpi=300, bbox_inches='tight')
    plt.close()

    # Plot 6: ROC-style visualization (TPR vs FPR by type)
    print("Generating TPR vs FPR scatter plot...")
    fig, ax = plt.subplots(figsize=(10, 8))

    scatter = ax.scatter(type_metrics['fpr'], type_metrics['tpr'],
                        s=type_metrics['total']*2, alpha=0.6, c=type_metrics['f1'],
                        cmap='viridis', edgecolors='black', linewidth=1)

    # Add diagonal line (random classifier)
    ax.plot([0, 1], [0, 1], 'r--', alpha=0.5, label='Random Classifier')

    # Annotate points
    for idx, row in type_metrics.iterrows():
        ax.annotate(row['type'], (row['fpr'], row['tpr']),
                   fontsize=8, alpha=0.7, xytext=(5, 5), textcoords='offset points')

    ax.set_xlabel('False Positive Rate', fontsize=12)
    ax.set_ylabel('True Positive Rate (Recall)', fontsize=12)
    ax.set_title('TPR vs FPR by Query Type\n(Bubble size = sample count, color = F1 score)',
                fontsize=14, fontweight='bold')
    ax.legend()
    ax.grid(alpha=0.3)

    cbar = plt.colorbar(scatter, ax=ax)
    cbar.set_label('F1 Score', fontsize=11)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/tpr_vs_fpr.png', dpi=300, bbox_inches='tight')
    plt.close()

    print(f"\n✓ All plots saved to {output_dir}/")


def save_results(overall_metrics, type_metrics, output_path):
    """Save results to JSON."""
    results = {
        'overall': overall_metrics,
        'by_type': type_metrics.to_dict('records')
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n✓ Results saved to {output_path}")


def main():
    """Main analysis function."""
    # Get model name from command line argument
    if len(sys.argv) > 1:
        model_name = sys.argv[1].lower()
    else:
        model_name = 'mistral'
        print("No model specified, defaulting to mistral")
        print("Usage: python analyze_results.py [model_name]")
        print("Available models: mistral, gemma, llama, qwen\n")

    # Define file paths based on model
    model_configs = {
        'mistral': {
            'input': '../data/mistral/nosql_injection_dataset_complete_mistral_labeled.json',
            'output': '../data/mistral/analysis_results.json',
            'plots': '../data/mistral/plots'
        },
        'gemma': {
            'input': '../data/gemma/gemma_labeled.json',
            'output': '../data/gemma/analysis_results.json',
            'plots': '../data/gemma/plots'
        },
        'llama': {
            'input': '../data/llama/llama_labeled.json',
            'output': '../data/llama/analysis_results.json',
            'plots': '../data/llama/plots'
        },
        'qwen': {
            'input': '../data/qwen/qwen_labeled.json',
            'output': '../data/qwen/analysis_results.json',
            'plots': '../data/qwen/plots'
        }
    }

    if model_name not in model_configs:
        print(f"Error: Unknown model '{model_name}'")
        print(f"Available models: {', '.join(model_configs.keys())}")
        sys.exit(1)

    config = model_configs[model_name]
    input_file = config['input']
    output_file = config['output']
    plots_dir = config['plots']

    print(f"Analyzing {model_name.upper()} model...")
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print(f"Plots:  {plots_dir}\n")

    print("Loading dataset...")
    df = load_data(input_file)

    print("Converting labels...")
    df = convert_labels(df)

    # Overall analysis
    overall_metrics = analyze_overall(df)

    # Type-specific analysis
    type_metrics = analyze_by_type(df)

    # Create visualizations
    print("\n" + "="*70)
    print("GENERATING VISUALIZATIONS")
    print("="*70)
    create_plots(df, overall_metrics, type_metrics, plots_dir)

    # Save results
    save_results(overall_metrics, type_metrics, output_file)

    print(f"\n✓ {model_name.upper()} analysis complete!")


if __name__ == "__main__":
    main()
