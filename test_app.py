import unittest
import tempfile
import os
import json
import sqlite3
from unittest.mock import patch, MagicMock
from app import app, initialize_database, validate_email, sanitize_input, get_db
import pyotp

class MFATestCase(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a temporary database file
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test_secret_key'
        
        # Override the DB_PATH for testing
        import app as app_module
        self.original_db_path = app_module.DB_PATH
        app_module.DB_PATH = app.config['DATABASE']
        
        self.app = app.test_client()
        
        with app.app_context():
            initialize_database()
    
    def tearDown(self):
        """Clean up after each test method."""
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])
        
        # Restore original DB_PATH
        import app as app_module
        app_module.DB_PATH = self.original_db_path
    
    def test_validate_email(self):
        """Test email validation function."""
        # Valid emails
        self.assertTrue(validate_email("test@example.com"))
        self.assertTrue(validate_email("user.name+tag@domain.co.uk"))
        self.assertTrue(validate_email("valid.email@subdomain.example.org"))
        
        # Invalid emails
        self.assertFalse(validate_email("invalid-email"))
        self.assertFalse(validate_email("@domain.com"))
        self.assertFalse(validate_email("user@"))
        self.assertFalse(validate_email(""))
        self.assertFalse(validate_email(None))
    
    def test_sanitize_input(self):
        """Test input sanitization function."""
        # Test XSS prevention
        self.assertEqual(sanitize_input("<script>alert('xss')</script>"), "&lt;script&gt;alert('xss')&lt;/script&gt;")
        self.assertEqual(sanitize_input("  normal text  "), "normal text")
        self.assertEqual(sanitize_input(""), "")
        self.assertIsNone(sanitize_input(None))
    
    def test_index_redirect(self):
        """Test that index redirects to login."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)
    
    def test_login_page_loads(self):
        """Test that login page loads correctly."""
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Secure Login', response.data)
    
    def test_register_page_loads(self):
        """Test that register page loads correctly."""
        response = self.app.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Create Account', response.data)
    
    def test_register_validation(self):
        """Test registration input validation."""
        # Test missing fields
        response = self.app.post('/register', data={
            'username': 'testuser',
            # missing email, password, pin
        }, follow_redirects=True)
        self.assertIn(b'All fields are required', response.data)
        
        # Test invalid email
        response = self.app.post('/register', data={
            'username': 'testuser',
            'email': 'invalid-email',
            'password': 'password123',
            'pin': '1234'
        }, follow_redirects=True)
        self.assertIn(b'valid email address', response.data)
        
        # Test invalid PIN
        response = self.app.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123',
            'pin': '123'  # too short
        }, follow_redirects=True)
        self.assertIn(b'PIN must be exactly 4 digits', response.data)
        
        # Test weak password
        response = self.app.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': '123',  # too short
            'pin': '1234'
        }, follow_redirects=True)
        self.assertIn(b'Password must be at least 8 characters', response.data)
    
    def test_successful_registration(self):
        """Test successful user registration."""
        response = self.app.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123',
            'pin': '1234'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Setup Complete', response.data)
        
        # Verify user was created in database
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", ('testuser',)).fetchone()
        self.assertIsNotNone(user)
        self.assertEqual(user['email'], 'test@example.com')
        conn.close()
    
    def test_duplicate_registration(self):
        """Test that duplicate usernames/emails are rejected."""
        # Register first user
        self.app.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123',
            'pin': '1234'
        })
        
        # Try to register with same username
        response = self.app.post('/register', data={
            'username': 'testuser',
            'email': 'different@example.com',
            'password': 'password123',
            'pin': '1234'
        }, follow_redirects=True)
        self.assertIn(b'Username already exists', response.data)
        
        # Try to register with same email
        response = self.app.post('/register', data={
            'username': 'differentuser',
            'email': 'test@example.com',
            'password': 'password123',
            'pin': '1234'
        }, follow_redirects=True)
        self.assertIn(b'Email already exists', response.data)
    
    def test_login_validation(self):
        """Test login input validation."""
        response = self.app.post('/login', data={
            'username': 'testuser',
            # missing other fields
        }, follow_redirects=True)
        self.assertIn(b'All fields are required', response.data)
    
    def test_failed_login(self):
        """Test failed login attempts."""
        response = self.app.post('/login', data={
            'username': 'nonexistent',
            'password': 'wrongpassword',
            'pin': '1234',
            'totp': '123456'
        }, follow_redirects=True)
        self.assertIn(b'Login failed', response.data)
    
    def test_dashboard_requires_auth(self):
        """Test that dashboard requires authentication."""
        response = self.app.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)
    
    def test_admin_requires_auth(self):
        """Test that admin page requires authentication."""
        response = self.app.get('/admin')
        self.assertEqual(response.status_code, 401)
    
    def test_api_users_requires_auth(self):
        """Test that API endpoints require authentication."""
        response = self.app.get('/api/users')
        self.assertEqual(response.status_code, 401)
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'Authentication required')
    
    def test_api_get_users_authenticated(self):
        """Test API users endpoint with authentication."""
        # Create a user and login
        self.create_test_user()
        
        with self.app.session_transaction() as sess:
            sess['user'] = 'testuser'
            sess['user_id'] = 1
        
        response = self.app.get('/api/users')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('data', data)
        self.assertEqual(data['count'], 1)
    
    def test_api_get_user_by_id(self):
        """Test API get specific user endpoint."""
        self.create_test_user()
        
        with self.app.session_transaction() as sess:
            sess['user'] = 'testuser'
            sess['user_id'] = 1
        
        response = self.app.get('/api/users/1')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['username'], 'testuser')
    
    def test_api_get_nonexistent_user(self):
        """Test API get non-existent user."""
        with self.app.session_transaction() as sess:
            sess['user'] = 'testuser'
            sess['user_id'] = 1
        
        response = self.app.get('/api/users/999')
        self.assertEqual(response.status_code, 404)
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'User not found')
    
    def test_api_update_user(self):
        """Test API update user endpoint."""
        self.create_test_user()
        
        with self.app.session_transaction() as sess:
            sess['user'] = 'testuser'
            sess['user_id'] = 1
        
        response = self.app.put('/api/users/1', 
                               data=json.dumps({'email': 'updated@example.com'}),
                               content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        
        # Verify the update
        conn = get_db()
        user = conn.execute("SELECT email FROM users WHERE id = 1").fetchone()
        self.assertEqual(user['email'], 'updated@example.com')
        conn.close()
    
    def test_api_update_user_invalid_email(self):
        """Test API update user with invalid email."""
        self.create_test_user()
        
        with self.app.session_transaction() as sess:
            sess['user'] = 'testuser'
            sess['user_id'] = 1
        
        response = self.app.put('/api/users/1', 
                               data=json.dumps({'email': 'invalid-email'}),
                               content_type='application/json')
        self.assertEqual(response.status_code, 400)
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'Invalid email format')
    
    def test_api_delete_user(self):
        """Test API delete user endpoint."""
        self.create_test_user()
        
        with self.app.session_transaction() as sess:
            sess['user'] = 'testuser'
            sess['user_id'] = 1
        
        response = self.app.delete('/api/users/1')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        
        # Verify the deletion
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = 1").fetchone()
        self.assertIsNone(user)
        conn.close()
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection attempts are prevented."""
        # Try SQL injection in username field
        malicious_username = "admin'; DROP TABLE users; --"
        
        response = self.app.post('/login', data={
            'username': malicious_username,
            'password': 'password',
            'pin': '1234',
            'totp': '123456'
        }, follow_redirects=True)
        
        # Should fail gracefully, not crash
        self.assertIn(b'Login failed', response.data)
        
        # Verify table still exists
        conn = get_db()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [table['name'] for table in tables]
        self.assertIn('users', table_names)
        conn.close()
    
    def test_audit_logging(self):
        """Test that audit events are logged."""
        self.create_test_user()
        
        # Check if audit log entry was created during user creation
        conn = get_db()
        audit_entries = conn.execute("SELECT * FROM audit_log WHERE action = 'USER_REGISTERED'").fetchall()
        self.assertGreaterEqual(len(audit_entries), 1)
        conn.close()
    
    def create_test_user(self):
        """Helper method to create a test user."""
        conn = get_db()
        from werkzeug.security import generate_password_hash
        import pyotp
        
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash('password123')
        pin_hash = generate_password_hash('1234')
        
        conn.execute(
            "INSERT INTO users (username, email, password_hash, pin_hash, totp_secret) VALUES (?, ?, ?, ?, ?)",
            ('testuser', 'test@example.com', password_hash, pin_hash, totp_secret)
        )
        conn.commit()
        conn.close()

class SecurityTestCase(unittest.TestCase):
    """Additional security-focused tests."""
    
    def test_xss_prevention(self):
        """Test XSS prevention in input sanitization."""
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<iframe src='javascript:alert(\"xss\")'></iframe>"
        ]
        
        for dangerous_input in dangerous_inputs:
            sanitized = sanitize_input(dangerous_input)
            self.assertNotIn('<script>', sanitized)
            self.assertNotIn('javascript:', sanitized)
            self.assertNotIn('onerror=', sanitized)
    
    def test_csrf_protection(self):
        """Test CSRF protection (basic check for secret key)."""
        self.assertTrue(app.secret_key)
        self.assertNotEqual(app.secret_key, "default_secret")

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(MFATestCase))
    test_suite.addTest(unittest.makeSuite(SecurityTestCase))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\nTests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")