# Vulnerability Research Plan: Open Source Code Analysis

---

## **Introduction**

This document outlines a structured plan to build a dataset of open source vulnerable code, inspired by Anthropic’s findings, and to evaluate the capability of advanced coding harnesses (e.g., OpenAI Codex, Gemini CLI) in detecting these vulnerabilities. The ultimate goal is to assess the validity of claims regarding the superiority of certain AI models in cybersecurity vulnerability detection.

---

## **Step 1: Build a Comprehensive Dataset of Vulnerable Open Source Code**

### **Objective**

Create a dataset containing:

- Open source repositories with known vulnerabilities
- Specific commits and files where vulnerabilities were introduced/fixed
- Detailed metadata (CVE IDs, vulnerability types, descriptions, etc.)
- A structured CSV/JSON file for easy analysis and sharing with researchers

---

### **Detailed Plan**

#### **1. Review Anthropic’s Report**

- **Action:** Thoroughly review the report based on Anthropic findings that details vulnerabilities found in open source projects.
- **Goal:** Extract key information such as:
  - Repository names and URLs
  - Commit hashes (where vulnerabilities were introduced/fixed)
  - File paths and specific lines of code
  - CVE IDs and vulnerability types (e.g., integer overflow, buffer overflow, use-after-free)
  - High-level descriptions of each vulnerability

---

#### **2. Extract Git Repositories and Relevant Commits**

- **Action:** Clone each identified repository.
- **Goal:** For each vulnerability:
  - Identify the exact commit hash where the vulnerability was introduced and/or fixed.
  - Use `git checkout` to navigate to the relevant commit.
  - Extract the specific file(s) containing the vulnerability.

---

#### **3. Build a Structured Dataset**

- **Action:** Create a CSV/JSON file with the following columns/fields:
  - Repository URL
  - Commit hash (vulnerable and fixed, if applicable)
  - File path
  - Vulnerability type (e.g., integer overflow, buffer overflow)
  - CVE ID (if available)
  - High-level description of the vulnerability
  - Code snippet (if possible)
  - Any additional metadata (e.g., programming language, severity score)
- **Goal:** Ensure the dataset is comprehensive, well-organized, and easy to analyze.

---

#### **4. Validate the Dataset**

- **Action:** Cross-reference the dataset with public vulnerability databases (e.g., NVD, GitHub Advisory Database) to ensure accuracy.
- **Goal:** Confirm that all entries are correct and complete.

---

## **Step 2: Evaluate AI Models’ Capability to Detect Vulnerabilities**

### **Objective**

Assess whether advanced AI models (e.g., OpenAI Codex, Gemini CLI) can detect vulnerabilities in the dataset when provided with:

- The vulnerable file(s)
- A prompt describing the potential vulnerability type (e.g., “Look for integer overflow in this C code”)

---

### **Detailed Plan**

#### **1. Select AI Models and Harnesses**

- **Action:** Choose the AI models/harnesses to test (e.g., OpenAI Codex, Gemini CLI).
- **Goal:** Ensure a diverse set of models to compare performance.

---

#### **2. Design Prompts for Vulnerability Detection**

- **Action:** Craft prompts that:
  - Provide the vulnerable file(s) to the model.
  - Describe the type of vulnerability to look for (e.g., “This file may contain a buffer overflow. Analyze it for potential vulnerabilities.”).
- **Goal:** Simulate a real-world scenario where a researcher or developer uses AI to audit code.

---

#### **3. Run Experiments**

- **Action:** For each vulnerability in the dataset:
  - Provide the file and prompt to the AI model.
  - Record the model’s output (e.g., detected vulnerabilities, false positives, false negatives).
- **Goal:** Collect data on the model’s detection capabilities.

---

#### **4. Analyze Results**

- **Action:** Compare the AI models’ outputs against the ground truth (the dataset).
- **Goal:** Determine:
  - How often the models correctly identify vulnerabilities.
  - How often they miss vulnerabilities (false negatives).
  - How often they flag non-vulnerable code (false positives).
  - Whether any model consistently outperforms others.

---

#### **5. Draw Conclusions**

- **Action:** Synthesize the results into a report.
- **Goal:** Answer the core question: *Are certain AI models uniquely capable of detecting critical vulnerabilities, or is this a result of targeted testing and dataset curation?*

---

## **Ultimate Goal**

- **Assess the Narrative:** Determine whether Anthropic’s claims about their models’ superiority in cybersecurity are justified, or if similar results could be achieved with other models and a well-curated dataset.
- **Contribute to Research:** Provide a public dataset and analysis to support further research in AI-assisted vulnerability detection.

---

## **Next Steps**

1. **Review the Anthropic report** and extract all relevant details.
2. **Build the dataset** of vulnerable repositories, commits, and files.
3. **Design and run experiments** using AI models.
4. **Analyze and report findings.**
