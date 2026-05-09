
import pytest
import sqlite3
import os
import json
from pathlib import Path
from server_doctor.storage.db import set_db_path, init_db, get_db
from server_doctor.storage.repositories import ScanJobRepository, ServerRepository
from server_doctor.model.server import ServerModel, NginxInfo, PHPInfo, ServiceStatus, CapabilityLevel

@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    return str(path)

@pytest.fixture
def repo_setup(db_path):
    # Use the helper to set the path
    set_db_path(db_path)
    # Initialize the database (create tables)
    init_db()
    return ServerRepository(), ScanJobRepository()

def test_server_repository(repo_setup):
    server_repo, _ = repo_setup
    
    # Add server
    server_id = server_repo.create(
        "Test Server",
        "127.0.0.1",
        22,
        "root",
        None,
        "/tmp/key",
        "tag1",
    )
    assert server_id > 0
    
    # List servers
    servers = server_repo.get_all()
    assert len(servers) == 1
    assert servers[0].name == "Test Server"
    
    # Get server
    server = server_repo.get_by_id(server_id)
    assert server.name == "Test Server"
    
    # Delete server
    server_repo.delete(server_id)
    assert len(server_repo.get_all()) == 0

def test_job_repository(repo_setup):
    server_repo, job_repo = repo_setup
    
    server_id = server_repo.create("Test", "127.0.0.1", 22, "root")
    
    # Create job
    job_id = job_repo.create(server_id)
    assert job_id > 0
    
    # Update status
    job_repo.update_status(job_id, "running", progress=50)
    job = job_repo.get_by_id(job_id)
    assert job.status == "running"
    assert job.progress == 50
    
    # Complete job
    diagnosis_data = {"root_cause": "Clean", "top_risks": []}
    job_repo.update_status(
        job_id, 
        status="success", 
        score=100, 
        summary="Scan completed successfully", 
        diagnosis_json=json.dumps(diagnosis_data)
    )
    job = job_repo.get_by_id(job_id)
    assert job.status == "success"
    assert job.score == 100


def test_job_repository_persists_repo_scan_paths(repo_setup):
    server_repo, job_repo = repo_setup

    server_id = server_repo.create("Test", "127.0.0.1", 22, "root")
    job_id = job_repo.create(server_id, repo_scan_paths="/var/www,/srv/app")

    job = job_repo.get_by_id(job_id)
    assert job is not None
    assert job.repo_scan_paths == "/var/www,/srv/app"
