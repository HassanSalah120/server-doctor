"""
Safe Apply implementation for Nginx config changes.

Implements the strict safety model:
1. Backup before edit
2. nginx -t validation
3. Rollback on failure
4. Reload only on success
"""

import re
from datetime import datetime
from typing import Optional

from server_doctor.connector.ssh import SSHConnector
from server_doctor.web.jobs import Job, JobStatus
from server_doctor.web.snippets import check_existing_marker


def create_backup_path(original_path: str) -> str:
    """Generate timestamped backup path.
    
    Args:
        original_path: Original file path.
        
    Returns:
        Backup path like /etc/nginx/backups/filename.bak-YYYYMMDD-HHMMSS
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = original_path.split("/")[-1]
    return f"/etc/nginx/backups/{filename}.bak-{timestamp}"


def find_server_block_end(content: str, domain: str) -> Optional[int]:
    """Find the position to insert snippet in server block.
    
    Finds the closing brace of the server block for the given domain.
    
    Args:
        content: Nginx config file content.
        domain: Domain to find server block for.
        
    Returns:
        Character position before closing brace, or None if not found.
    """
    # Find server block containing this domain
    # Pattern: server { ... server_name domain; ... }
    
    # First find server_name with our domain
    pattern = rf'server_name[^;]*\b{re.escape(domain)}\b[^;]*;'
    match = re.search(pattern, content)
    
    if not match:
        return None
    
    # Now find the server block boundaries
    # Work backwards from server_name to find the opening brace
    pos = match.start()
    
    # Find "server" keyword before this position
    server_pattern = r'\bserver\s*\{'
    server_matches = list(re.finditer(server_pattern, content[:pos]))
    
    if not server_matches:
        return None
    
    # Use the last match (closest to our server_name)
    server_start = server_matches[-1].start()
    
    # Now find the matching closing brace
    brace_count = 0
    in_server = False
    
    for i, char in enumerate(content[server_start:], start=server_start):
        if char == '{':
            brace_count += 1
            in_server = True
        elif char == '}':
            brace_count -= 1
            if in_server and brace_count == 0:
                # Found the closing brace
                return i
    
    return None


def insert_snippet_in_server_block(content: str, domain: str, snippet: str) -> Optional[str]:
    """Insert snippet into the correct server block.
    
    Args:
        content: Nginx config file content.
        domain: Domain to find server block for.
        snippet: Snippet to insert.
        
    Returns:
        Modified content, or None if server block not found.
    """
    end_pos = find_server_block_end(content, domain)
    
    if end_pos is None:
        return None
    
    # Insert snippet before the closing brace with proper indentation
    indented_snippet = "\n    " + snippet.replace("\n", "\n    ") + "\n"
    
    return content[:end_pos] + indented_snippet + content[end_pos:]


def run_safe_apply(
    ssh: SSHConnector,
    job: Job,
    nginx_file: str,
    domain: str,
    snippet: str,
    websocket_snippet: Optional[str] = None,
) -> None:
    """Execute safe apply with backup and rollback.
    
    Args:
        ssh: SSH connector.
        job: Job for logging.
        nginx_file: Path to Nginx config file.
        domain: Target domain.
        snippet: Main snippet to insert.
        websocket_snippet: Optional WebSocket snippet.
    """
    backup_path: Optional[str] = None
    
    try:
        # Step 1: Read current config
        job.log_info(f"Reading config file: {nginx_file}")
        original_content = ssh.read_file(nginx_file)
        
        if original_content is None:
            job.log_error(f"Failed to read config file: {nginx_file}")
            job.status = JobStatus.FAILED
            return
        
        # Step 2: Check for existing marker (prevent duplicates)
        path_match = re.search(r'project:\s*(/[^\s(]+)', snippet)
        if path_match:
            proj_path = path_match.group(1)
            if check_existing_marker(original_content, proj_path):
                job.log_error(f"Project marker for {proj_path} already exists. Refusing to insert duplicate.")
                job.status = JobStatus.FAILED
                return
        
        # Step 3: Create backup
        job.log_info("Creating backup...")
        backup_path = create_backup_path(nginx_file)
        
        # Ensure backup directory exists
        ssh.run("mkdir -p /etc/nginx/backups")
        
        # Copy to backup
        result = ssh.run(f"cp '{nginx_file}' '{backup_path}'")
        if not result.success:
            job.log_error(f"Failed to create backup: {result.stderr}")
            job.status = JobStatus.FAILED
            return
        
        job.log_success(f"Backup created: {backup_path}")
        job.result["backup_path"] = backup_path
        
        # Step 4: Insert snippet
        job.log_info(f"Inserting snippet into server block for {domain}...")
        
        new_content = insert_snippet_in_server_block(original_content, domain, snippet)
        
        if new_content is None:
            job.log_error(f"Could not find server block for domain: {domain}")
            job.status = JobStatus.FAILED
            return
        
        # Insert WebSocket snippet if provided
        if websocket_snippet:
            job.log_info("Inserting WebSocket snippet...")
            new_content = insert_snippet_in_server_block(new_content, domain, websocket_snippet)
            if new_content is None:
                job.log_error("Failed to insert WebSocket snippet")
                job.status = JobStatus.FAILED
                return
        
        # Step 5: Write new config
        job.log_info("Writing new configuration...")
        
        # Use a temp file and mv for atomic write
        temp_file = f"/tmp/nginx_conf_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Write content via base64 to avoid shell escaping issues
        import base64
        encoded = base64.b64encode(new_content.encode()).decode()
        result = ssh.run(f"echo '{encoded}' | base64 -d > '{temp_file}'")
        
        if not result.success:
            job.log_error(f"Failed to write temp file: {result.stderr}")
            job.status = JobStatus.FAILED
            return
        
        # Move to target
        result = ssh.run(f"mv '{temp_file}' '{nginx_file}'")
        if not result.success:
            job.log_error(f"Failed to move config file: {result.stderr}")
            job.status = JobStatus.FAILED
            return
        
        job.log_success("Configuration updated")
        
        # Step 6: Test nginx config
        job.log_info("Running nginx -t...")
        result = ssh.run("nginx -t 2>&1")
        
        job.result["nginx_test_output"] = result.stdout + result.stderr
        
        if not result.success:
            # ROLLBACK
            job.log_error("nginx -t FAILED! Rolling back...")
            job.log_error(result.stderr)
            
            rollback_result = ssh.run(f"cp '{backup_path}' '{nginx_file}'")
            if rollback_result.success:
                job.log_success("Rollback completed - original config restored")
                job.result["rollback"] = True
            else:
                job.log_error(f"CRITICAL: Rollback failed! Manual intervention required. Backup at: {backup_path}")
                job.result["rollback"] = False
            
            job.status = JobStatus.FAILED
            return
        
        job.log_success("nginx -t passed")
        
        # Step 7: Reload nginx
        job.log_info("Reloading nginx...")
        result = ssh.run("systemctl reload nginx")
        
        if result.success:
            job.log_success("nginx reloaded successfully")
            job.result["nginx_reloaded"] = True
        else:
            # Try alternative reload method
            result = ssh.run("nginx -s reload")
            if result.success:
                job.log_success("nginx reloaded successfully (via nginx -s)")
                job.result["nginx_reloaded"] = True
            else:
                job.log_warn(f"Warning: nginx reload failed: {result.stderr}")
                job.result["nginx_reloaded"] = False
        
        job.result["files_modified"] = [nginx_file]
        
    except Exception as e:
        job.log_error(f"Unexpected error: {str(e)}")
        
        # Attempt rollback on any error
        if backup_path:
            job.log_info("Attempting emergency rollback...")
            try:
                rollback_result = ssh.run(f"cp '{backup_path}' '{nginx_file}'")
                if rollback_result.success:
                    job.log_success("Emergency rollback completed")
                    job.result["rollback"] = True
            except Exception:
                job.log_error(f"Emergency rollback failed! Backup at: {backup_path}")
        
        job.status = JobStatus.FAILED
