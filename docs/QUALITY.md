## **4\. Development Standards & Quality Gates**

### **4.1 Test-Driven Development (TDD) Mandate**

Engineers must write tests **before** implementation using the **Red-Green-Refactor** cycle.

1. **Red (Write Test):** Create a failing test in tests/unit/actions/... covering a small piece of functionality.
2. **Green (Write Code):** Implement the minimal code in src/actions/ to make the test pass.
3. **Refactor:** Improve code structure without changing behavior.
4. **Repeat:** Proceed to the next small functionality.

### **4.3 Task Tracking (Beads Hierarchy)**

We use **Beads** for task management. We strictly utilize the hierarchical ID feature for granularity.

* **Structure:**
  * **Epic (bd-xxxx):** High-level Feature (e.g., "Implement Entra ID Revocation").
  * **Task (bd-xxxx.1):** Specific Tool Implementation (e.g., entra.user.revokeSignInSessions).
  * **Sub-task (bd-xxxx.1.1):** Development Step (e.g., "TDD Setup & Mocks").
* **Mandatory Subtask Flow:**
  1. fluf-xxxx.1.1: **TDD Setup** (Write mocks and failing unit tests).
  2. fluf-xxxx.1.2: **Implementation** (Write code to pass tests).
  3. fluf-xxxx.1.3: **Refactor & QA** (Run make test, make lint, ensure coverage \>70%).

### **4.4 Git & Source Control**

* **Commit Frequency:** One commit per significant improvement or sub-task completion.
* **Commit Message Format:**
  * Header: \<keyword\>: \<summary\> (e.g., feat: Add user authentication)
  * Body: Detailed explanation.
  * Footer: Signed-off-by: Name \<email\>
* **AI Identity:** If using AI tools (Copilot, Cursor), configure a specific git identity:
  * git config \--local user.name "AI Assistant"
  * git config \--local user.email "ai@cygo-entrepreneurs.com"

### **4.5 Documentation**

* **Centralized Truth:** All implementation details, technical decisions, and "how-to" guides must be documented in docs/IMPLEMENTATION\_SUMMARY.md.
* **Workflow:** Documentation is written alongside code.

### **4.6 Quality Metrics (Enforced via CI/Makefile)**

* **Coverage:** \>70%.
* **Linting:**
  * flake8: Max line length **89**.
  * isort: Mandatory import sorting.
* **Typing:** mypy strict mode.
* **Formatting:** black.

### **4.7 The Makefile**

The project root must contain a Makefile with these standard targets:

.PHONY: test lint format install run init-tasks verify-beads

install:
	pip install \-r requirements.txt
	pip install beads-task

init-tasks:
	bead init

test:
	pytest tests/unit \--cov=src \--cov-report=term-missing \--cov-fail-under=70

lint:
	flake8 src tests \--max-line-length=89
	isort src tests \--check-only
	mypy src tests
	black src tests \--check

format:
	isort src tests
	black src tests

run:
	python \-m src.app

