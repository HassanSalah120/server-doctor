"""Decision Engine - Rule-based reasoning for recommendations.

This engine aggregates findings from analyzers and produces
ranked recommendations (best → acceptable → risky).
"""

from dataclasses import dataclass, field
from enum import Enum

from server_doctor.model.finding import Finding
from server_doctor.model.server import ProjectInfo, ProjectType, ServerModel


class SolutionRank(Enum):
    """Ranking of solution quality."""

    BEST_PRACTICE = "best"      # Recommended approach
    ACCEPTABLE = "acceptable"   # Works but not ideal
    RISKY = "risky"             # Possible but dangerous


@dataclass
class Solution:
    """A proposed solution for a finding."""

    rank: SolutionRank
    description: str
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class Recommendation:
    """A recommendation with ranked solutions."""

    finding: Finding
    solutions: list[Solution] = field(default_factory=list)
    summary: str = ""


class DecisionEngine:
    """Rule-based decision engine.

    Produces ranked recommendations based on findings and context.
    Never makes decisions without evidence.
    """

    def __init__(self, model: ServerModel, findings: list[Finding]) -> None:
        self.model = model
        self.findings = findings

    def recommend(self) -> list[Recommendation]:
        """Generate recommendations for all findings.

        Returns:
            List of Recommendation objects with ranked solutions.
        """
        recommendations: list[Recommendation] = []

        for finding in self.findings:
            # Skip findings that are derived from another finding to avoid redundant actions
            if finding.derived_from:
                continue
                
            recommendation = self._generate_recommendation(finding)
            if recommendation:
                recommendations.append(recommendation)

        return recommendations

    def _generate_recommendation(self, finding: Finding) -> Recommendation:
        """Generate recommendation for a single finding."""
        recommendation = Recommendation(
            finding=finding,
            summary=f"[{finding.id}] {finding.condition}",
        )

        # Route to specific handlers based on ID or condition
        if finding.id == "NGX004": # Laravel root
            recommendation.solutions = self._solutions_for_laravel_root(finding)
        elif finding.id == "NGX005": # try_files
            recommendation.solutions = self._solutions_for_try_files(finding)
        elif finding.id == "NGX003": # socket
            recommendation.solutions = self._solutions_for_socket_mismatch(finding)
        elif finding.id == "NGX001": # backup
            recommendation.solutions = self._solutions_for_backup(finding)
        elif finding.id == "NGX002": # duplicate
            recommendation.solutions = self._solutions_for_duplicate(finding)
        else:
            # Generic solution
            recommendation.solutions = [
                Solution(
                    rank=SolutionRank.BEST_PRACTICE,
                    description=finding.treatment,
                )
            ]

        return recommendation

    def _solutions_for_laravel_root(self, finding: Finding) -> list[Solution]:
        """Generate solutions for Laravel root misconfiguration."""
        return [
            Solution(
                rank=SolutionRank.BEST_PRACTICE,
                description="Use subdomain deployment",
                steps=[
                    "Create new server block for subdomain",
                    "Set root to /path/to/project/public",
                    "Enable the new site configuration",
                    "Remove old sub-path configuration",
                ],
            ),
            Solution(
                rank=SolutionRank.ACCEPTABLE,
                description="Fix root to point to /public",
                steps=[
                    f"Change: {finding.treatment}",
                    "Run: nginx -t",
                    "Reload: systemctl reload nginx",
                ],
            ),
            Solution(
                rank=SolutionRank.RISKY,
                description="Use alias for sub-path deployment",
                steps=[
                    "Add alias directive pointing to /public",
                    "Configure try_files for Laravel routing",
                    "Test thoroughly for asset loading",
                ],
                warnings=[
                    "Sub-path Laravel is non-standard",
                    "Asset paths may require manual fixing",
                    "Framework assumptions may break",
                ],
            ),
        ]

    def _solutions_for_try_files(self, finding: Finding) -> list[Solution]:
        """Generate solutions for missing try_files."""
        return [
            Solution(
                rank=SolutionRank.BEST_PRACTICE,
                description="Add try_files for framework routing",
                steps=[
                    f"Add: {finding.treatment}",
                    "Run: nginx -t",
                    "Reload: systemctl reload nginx",
                ],
            ),
        ]

    def _solutions_for_socket_mismatch(self, finding: Finding) -> list[Solution]:
        """Generate solutions for PHP socket mismatch."""
        sockets = self.model.php.sockets if self.model.php else []

        solutions = []
        if sockets:
            solutions.append(
                Solution(
                    rank=SolutionRank.BEST_PRACTICE,
                    description=f"Use available socket: {sockets[0]}",
                    steps=[
                        f"Change fastcgi_pass to unix:{sockets[0]}",
                        "Run: nginx -t",
                        "Reload: systemctl reload nginx",
                    ],
                )
            )

        solutions.append(
            Solution(
                rank=SolutionRank.ACCEPTABLE,
                description="Install/start PHP-FPM for expected version",
                steps=[
                    "apt install php8.2-fpm",
                    "systemctl start php8.2-fpm",
                    "Check socket is created",
                ],
            )
        )

        return solutions

    def _solutions_for_duplicate(self, finding: Finding) -> list[Solution]:
        """Generate solutions for duplicate configurations."""
        return [
            Solution(
                rank=SolutionRank.BEST_PRACTICE,
                description="Remove duplicate server block",
                steps=[
                    "Identify which configuration is correct",
                    "Disable or remove the duplicate",
                    "Run: nginx -t",
                    "Reload: systemctl reload nginx",
                ],
            ),
            Solution(
                rank=SolutionRank.ACCEPTABLE,
                description="Rename one of the server_names",
                steps=[
                    "Change server_name in one block",
                    "Update DNS if needed",
                    "Test both configurations",
                ],
            ),
        ]

    def _solutions_for_backup(self, finding: Finding) -> list[Solution]:
        """Generate solutions for backup files."""
        # Extract files from evidence, deduplicate and ignore non-config files
        backup_files = sorted(list({
            e.source_file for e in finding.evidence 
            if e.source_file not in ("nginx.conf", "unknown")
        }))
        
        return [
            Solution(
                rank=SolutionRank.BEST_PRACTICE,
                description="Move backups out of include paths",
                steps=[f"Move to /etc/nginx/backups/: {f}" for f in backup_files] + [
                    "Run: nginx -t",
                    "Reload: systemctl reload nginx",
                ],
            ),
            Solution(
                rank=SolutionRank.ACCEPTABLE,
                description="Rename to .disabled",
                steps=[f"mv {f} {f}.disabled" for f in backup_files] + [
                    "Ensure include globs don't match .disabled",
                    "Run: nginx -t",
                    "Reload: systemctl reload nginx",
                ],
            ),
        ]
