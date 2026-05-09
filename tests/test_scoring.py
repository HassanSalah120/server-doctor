"""Tests for Scoring Engine.

Verifies deterministic scoring rules:
- Max Score: 100
- Categories: Security (40), Performance (20), Architecture (20), App (20)
- Penalties: exploitability-aware (base Critical -8, Warning -3, Info -0 with modifiers)
- Min score per category: 0
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.engine.scoring import ScoringEngine, ServerScore
from unittest.mock import MagicMock
from server_doctor.model.finding import Finding, Severity

def test_perfect_score():
    """No findings should yield 100 points."""
    engine = ScoringEngine()
    score = engine.calculate([])
    
    assert score.total == 100
    assert score.security.current_points == 40
    assert score.performance.current_points == 20
    assert score.architecture.current_points == 20
    assert score.app.current_points == 20

def test_critical_security_penalty():
    """One critical security finding should deduct base 8 points from Security."""
    f = Finding(
        id="NGX-SEC-3", # Security category
        condition="Dotfiles exposed",
        cause="Missing location block",
        treatment="Add block",
        severity=Severity.CRITICAL,
        confidence=1.0,
        evidence=[MagicMock()]
    )
    
    engine = ScoringEngine()
    score = engine.calculate([f])
    
    assert score.security.current_points == 32 # 40 - 8
    assert score.total == 92
    
def test_category_floor():
    """Score should not go below 0 per category."""
    # 5 Critical Security Findings = -50 points
    findings = []
    for i in range(5):
        findings.append(Finding(
            id="NGX-SEC-X",
            condition="Bad stuff",
            cause="...",
            treatment="...",
            severity=Severity.CRITICAL,
            confidence=1.0,
            evidence=[MagicMock()]
        ))
        
    engine = ScoringEngine()
    score = engine.calculate(findings)
    
    assert score.security.current_points == 0 # Floor at 0, not -10
    assert score.total == 60 # 0 + 20 + 20 + 20

def test_mixed_categories():
    """Verify mixed findings affect correct buckets."""
    findings = [
        Finding(id="NGX-PERF-1", severity=Severity.WARNING, condition="Gzip off", cause="", treatment="", confidence=1.0, evidence=[MagicMock()]),
        Finding(id="LARAVEL-1", severity=Severity.CRITICAL, condition="Debug on", cause="", treatment="", confidence=1.0, evidence=[MagicMock()]),
        Finding(id="PORT-1", severity=Severity.INFO, condition="Orphan port", cause="", treatment="", confidence=1.0, evidence=[MagicMock()]),
    ]
    
    engine = ScoringEngine()
    score = engine.calculate(findings)
    
    assert score.performance.current_points == 17 # 20 - 3
    assert score.app.current_points == 12 # 20 - 8
    assert score.architecture.current_points == 20 # 20 - 0
    assert score.total == 89


def test_dev_port_closure_meaningfully_improves_score():
    """Closing a public dev port should produce a clear score improvement."""
    engine = ScoringEngine()
    dev_exposed = [
        Finding(
            id="NGX000-2",
            severity=Severity.CRITICAL,
            condition="Docker port 5173 is exposed publicly bypassing Nginx",
            cause="dev port public",
            treatment="bind localhost",
            confidence=1.0,
            evidence=[MagicMock()],
        )
    ]
    before = engine.calculate(dev_exposed).total
    after = engine.calculate([]).total
    assert after - before >= 8
