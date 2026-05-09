# Contributing to Server Doctor

Thank you for your interest in contributing to Server Doctor! We welcome all contributions, from bug reports and feature requests to code changes and documentation improvements.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

If you find a bug, please [open an issue](https://github.com/HassanSalah120/server-doctor/issues/new?template=bug_report.md) and include:

- A clear description of the issue.
- Steps to reproduce the bug.
- Any relevant logs or screenshots.
- Details about your environment (OS, Nginx version, PHP version, Server Doctor version).

### Suggesting Features

We welcome feature requests! Please [open an issue](https://github.com/HassanSalah120/server-doctor/issues/new?template=feature_request.md) and explain:

- What feature you'd like to see.
- Why it would be useful.
- How you imagine it working.

### Submitting Pull Requests

1. Fork the repository and create your branch from `master`.
2. Install dependencies: `pip install -e .[dev]`
3. Ensure your code follows the project's style and passes all existing tests:
   ```bash
   python -m pytest
   ```
4. For frontend changes, build and test the web UI:
   ```bash
   cd web-ui
   npm ci
   npm run build
   ```
5. If you've added new features, please add corresponding tests.
6. Submit your pull request with a clear description of the changes.

## Development Setup

Server Doctor is built with Python (backend) and TypeScript/React (frontend web UI), using `pytest` for testing.

### Backend Setup

```bash
# Clone your fork
git clone https://github.com/HassanSalah120/server-doctor.git
cd server-doctor

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e .[dev]
```

### Frontend Setup

```bash
cd web-ui
npm ci
npm run dev  # For development
npm run build  # For production build
```

### Running Tests

```bash
# Backend tests
python -m pytest

# With coverage
python -m pytest --cov=server_doctor

# Frontend tests (if any)
cd web-ui
npm test
```

### Building Documentation

The project uses Markdown files for documentation. Ensure any changes are reflected in the relevant `.md` files.

## Project Structure

- `src/server_doctor/`: Main Python package
- `web-ui/`: React frontend
- `tests/`: Python test suite
- `docs/`: Additional documentation
- `fix-pack/`: Hardening scripts

## Coding Standards

- Use `ruff` for linting and formatting
- Follow PEP 8 for Python code
- Use type hints where possible
- Write tests for new features

## Questions?

If you have any questions, feel free to open an issue or reach out to the maintainers.

# Install in editable mode with dev dependencies
pip install -e .
```

## Questions?

If you have any questions, feel free to open an issue or reach out to the maintainers.
