"""
Comprehensive test suite for FastAPI file management application
Following industry best practices with fixtures, mocking, and proper test isolation
"""

import pytest
import pytest_asyncio
import os
import json
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
import pandas as pd
from io import BytesIO

# Import your app and models
from main import app, get_current_user, hash_password, verify_password, create_access_token
from models import Base, User, File as FileModel
from dbconn import get_db

# ==================== FIXTURES ====================

@pytest_asyncio.fixture(scope="function")
async def test_db():
    """Create a clean test database for each test"""
    # Use in-memory SQLite for testing
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def client(test_db):
    """Create test client with database override"""
    async def override_get_db():
        yield test_db
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(test_db):
    """Create a test user in the database"""
    user = User(
        name="Test User",
        email="test@example.com",
        password=hash_password("testpassword123"),
        status="active",
        role="user"
    )
    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)
    return user


@pytest_asyncio.fixture
async def auth_token(test_user):
    """Generate authentication token for test user"""
    token = create_access_token(
        data={"sub": test_user.email, "user_id": test_user.id},
        expires_delta=timedelta(minutes=30)
    )
    return token


@pytest_asyncio.fixture
async def auth_headers(auth_token):
    """Create authorization headers"""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def sample_csv_file():
    """Create a sample CSV file for testing"""
    df = pd.DataFrame({
        'name': ['Alice', 'Bob', 'Charlie'],
        'age': [25, 30, 35],
        'city': ['NY', 'LA', 'SF']
    })
    
    csv_buffer = BytesIO()
    df.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)
    return csv_buffer


@pytest.fixture
def sample_excel_file():
    """Create a sample Excel file for testing"""
    df = pd.DataFrame({
        'product': ['A', 'B', 'C'],
        'price': [10.5, 20.0, 15.75],
        'quantity': [100, 200, 150]
    })
    
    excel_buffer = BytesIO()
    df.to_excel(excel_buffer, index=False)
    excel_buffer.seek(0)
    return excel_buffer


@pytest_asyncio.fixture
async def uploaded_file(test_db, test_user):
    """Create a file record in the database"""
    file_record = FileModel(
        user_id=test_user.id,
        file_name="test_file.csv",
        file_size=1024,
        file_path="uploads/test.csv",
        file_format="csv",
        status="uploaded"
    )
    test_db.add(file_record)
    await test_db.commit()
    await test_db.refresh(file_record)
    return file_record


# ==================== UTILITY FUNCTION TESTS ====================

class TestUtilityFunctions:
    """Test password hashing and token generation"""
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "mySecurePassword123"
        hashed = hash_password(password)
        
        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$pbkdf2-sha256$")
    
    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        password = "mySecurePassword123"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        password = "mySecurePassword123"
        hashed = hash_password(password)
        
        assert verify_password("wrongPassword", hashed) is False
    
    def test_create_access_token(self):
        """Test JWT token creation"""
        data = {"sub": "test@example.com", "user_id": 1}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_create_access_token_with_expiry(self):
        """Test JWT token creation with custom expiry"""
        data = {"sub": "test@example.com", "user_id": 1}
        expires = timedelta(hours=2)
        token = create_access_token(data, expires_delta=expires)
        
        assert isinstance(token, str)


# ==================== AUTHENTICATION TESTS ====================

class TestAuthentication:
    """Test user registration and login endpoints"""
    
    @pytest.mark.asyncio
    async def test_register_user_success(self, client):
        """Test successful user registration"""
        user_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "securePass123"
        }
        
        response = await client.post("/register", json=user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert data["email"] == user_data["email"]
        assert data["name"] == user_data["name"]
        assert "id" in data
    
    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client, test_user):
        """Test registration with existing email"""
        user_data = {
            "name": "Another User",
            "email": test_user.email,
            "password": "password123"
        }
        
        response = await client.post("/register", json=user_data)
        
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_register_invalid_email(self, client):
        """Test registration with invalid email format"""
        user_data = {
            "name": "Test User",
            "email": "invalid-email",
            "password": "password123"
        }
        
        response = await client.post("/register", json=user_data)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_login_success(self, client, test_user):
        """Test successful login"""
        login_data = {
            "email": test_user.email,
            "password": "testpassword123"
        }
        
        response = await client.post("/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client, test_user):
        """Test login with wrong password"""
        login_data = {
            "email": test_user.email,
            "password": "wrongPassword"
        }
        
        response = await client.post("/login", json=login_data)
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        """Test login with non-existent email"""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "password123"
        }
        
        response = await client.post("/login", json=login_data)
        
        assert response.status_code in [401, 404]
    
    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client, test_db):
        """Test login with inactive user account"""
        inactive_user = User(
            name="Inactive User",
            email="inactive@example.com",
            password=hash_password("password123"),
            status="deleted",
            role="user"
        )
        test_db.add(inactive_user)
        await test_db.commit()
        
        login_data = {
            "email": inactive_user.email,
            "password": "password123"
        }
        
        response = await client.post("/login", json=login_data)
        
        assert response.status_code == 404


# ==================== FILE UPLOAD TESTS ====================

class TestFileUpload:
    """Test file upload functionality"""
    
    @pytest.mark.asyncio
    async def test_upload_csv_success(self, client, auth_headers, sample_csv_file):
        """Test successful CSV file upload"""
        files = {"file": ("test.csv", sample_csv_file, "text/csv")}
        
        response = await client.post(
            "/upload_file",
            files=files,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["file_format"] == "csv"
        assert "file_id" in data
    
    @pytest.mark.asyncio
    async def test_upload_excel_success(self, client, auth_headers, sample_excel_file):
        """Test successful Excel file upload"""
        files = {"file": ("test.xlsx", sample_excel_file, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        
        response = await client.post(
            "/upload_file",
            files=files,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["file_format"] == "xlsx"
    
    @pytest.mark.asyncio
    async def test_upload_invalid_format(self, client, auth_headers):
        """Test upload with unsupported file format"""
        invalid_file = BytesIO(b"This is a text file")
        files = {"file": ("test.txt", invalid_file, "text/plain")}
        
        response = await client.post(
            "/upload_file",
            files=files,
            headers=auth_headers
        )
        
        assert response.status_code == 400
        assert "files allowed" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_upload_without_auth(self, client, sample_csv_file):
        """Test file upload without authentication"""
        files = {"file": ("test.csv", sample_csv_file, "text/csv")}
        
        response = await client.post("/upload_file", files=files)
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_upload_corrupted_file(self, client, auth_headers):
        """Test upload with corrupted CSV file"""
        corrupted_csv = BytesIO(b"Invalid,CSV,Data\nWith,Mismatched\nColumns")
        files = {"file": ("corrupted.csv", corrupted_csv, "text/csv")}
        
        response = await client.post(
            "/upload_file",
            files=files,
            headers=auth_headers
        )
        
        # Should either reject or handle gracefully
        assert response.status_code in [200, 400]


# ==================== FILE READ TESTS ====================

class TestFileRead:
    """Test file reading functionality"""
    
    @pytest.mark.asyncio
    @patch('main.redis_client')
    async def test_read_file_success(self, mock_redis, client, auth_headers, uploaded_file, test_db):
        """Test successful file reading"""
        # Mock Redis to return None (no cache)
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock(return_value=True)
        
        # Create actual test file
        df = pd.DataFrame({'col1': [1, 2, 3], 'col2': ['a', 'b', 'c']})
        os.makedirs("uploads", exist_ok=True)
        df.to_csv(uploaded_file.file_path, index=False)
        
        try:
            response = await client.get(
                f"/read_file?file_id={uploaded_file.id}",
                headers=auth_headers
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["file_id"] == uploaded_file.id
            assert "rows" in data
        finally:
            # Cleanup
            if os.path.exists(uploaded_file.file_path):
                os.remove(uploaded_file.file_path)
    
    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, client, auth_headers):
        """Test reading non-existent file"""
        response = await client.get(
            "/read_file?file_id=99999",
            headers=auth_headers
        )
        
        assert response.status_code == 404
    
    @pytest.mark.asyncio
    @patch('main.redis_client')
    async def test_read_file_with_pagination(self, mock_redis, client, auth_headers, uploaded_file):
        """Test file reading with pagination parameters"""
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock(return_value=True)
        
        df = pd.DataFrame({'col1': range(100), 'col2': range(100, 200)})
        os.makedirs("uploads", exist_ok=True)
        df.to_csv(uploaded_file.file_path, index=False)
        
        try:
            response = await client.get(
                f"/read_file?file_id={uploaded_file.id}&page=2&page_size=20",
                headers=auth_headers
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["page"] == 2
            assert data["page_size"] == 20
        finally:
            if os.path.exists(uploaded_file.file_path):
                os.remove(uploaded_file.file_path)
    
    @pytest.mark.asyncio
    @patch('main.redis_client')
    async def test_read_file_from_cache(self, mock_redis, client, auth_headers, uploaded_file):
        """Test reading file from Redis cache"""
        cached_data = {
            "file_id": uploaded_file.id,
            "cached": True,
            "rows": []
        }
        mock_redis.get = AsyncMock(return_value=json.dumps(cached_data))
        
        response = await client.get(
            f"/read_file?file_id={uploaded_file.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["cached"] is True


# ==================== FILE MANAGEMENT TESTS ====================

class TestFileManagement:
    """Test file listing and deletion"""
    
    @pytest.mark.asyncio
    async def test_view_files_success(self, client, auth_headers, uploaded_file):
        """Test viewing user's files"""
        response = await client.get("/view_files", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["file_id"] == uploaded_file.id
    
    @pytest.mark.asyncio
    async def test_view_files_empty(self, client, auth_headers):
        """Test viewing files when user has none"""
        response = await client.get("/view_files", headers=auth_headers)
        
        assert response.status_code == 200
        assert response.json() == []
    
    @pytest.mark.asyncio
    async def test_delete_file_success(self, client, uploaded_file, test_db):
        """Test successful file deletion"""
        # Create dummy file
        os.makedirs("uploads", exist_ok=True)
        with open(uploaded_file.file_path, "w") as f:
            f.write("test content")
        
        try:
            response = await client.delete(f"/delete_file/{uploaded_file.id}")
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            
            # Verify file is marked as deleted
            await test_db.refresh(uploaded_file)
            assert uploaded_file.status == "deleted"
        finally:
            if os.path.exists(uploaded_file.file_path):
                os.remove(uploaded_file.file_path)
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_file(self, client):
        """Test deleting non-existent file"""
        response = await client.delete("/delete_file/99999")
        
        assert response.status_code == 404


# ==================== USER MANAGEMENT TESTS ====================

class TestUserManagement:
    """Test user deletion"""
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self, client, auth_headers, test_user, test_db):
        """Test successful user deletion (soft delete)"""
        response = await client.delete("/delete_user", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        
        # Verify user is marked as deleted
        await test_db.refresh(test_user)
        assert test_user.status == "deleted"
    
    @pytest.mark.asyncio
    async def test_delete_user_without_auth(self, client):
        """Test user deletion without authentication"""
        response = await client.delete("/delete_user")
        
        assert response.status_code == 401


# ==================== HEALTH CHECK TESTS ====================

class TestHealthCheck:
    """Test health check endpoint"""
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, client):
        """Test health check with working database"""
        response = await client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "connected"


# ==================== INTEGRATION TESTS ====================

class TestIntegrationScenarios:
    """Test complete user workflows"""
    
    @pytest.mark.asyncio
    async def test_complete_user_workflow(self, client, sample_csv_file):
        """Test complete workflow: register, login, upload, read, delete"""
        # 1. Register
        user_data = {
            "name": "Integration Test",
            "email": "integration@test.com",
            "password": "testPass123"
        }
        response = await client.post("/register", json=user_data)
        assert response.status_code == 201
        
        # 2. Login
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        response = await client.post("/login", json=login_data)
        assert response.status_code == 200
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 3. Upload file
        files = {"file": ("test.csv", sample_csv_file, "text/csv")}
        response = await client.post("/upload_file", files=files, headers=headers)
        assert response.status_code == 200
        file_id = response.json()["file_id"]
        
        # 4. View files
        response = await client.get("/view_files", headers=headers)
        assert response.status_code == 200
        assert len(response.json()) == 1
        
        # 5. Delete file
        response = await client.delete(f"/delete_file/{file_id}")
        assert response.status_code == 200
        
        # 6. Delete user
        response = await client.delete("/delete_user", headers=headers)
        assert response.status_code == 200


# ==================== CONFIGURATION ====================

# Run with: pytest test_main.py -v --asyncio-mode=auto
# For coverage: pytest test_main.py --cov=main --cov-report=html