// // Show or hide user creation form
// function showCreateUserForm() {
//     document.getElementById('user-form').style.display = 'block';
// }

// // Show or hide role creation form
// function showCreateRoleForm() {
//     document.getElementById('role-form').style.display = 'block';
// }

// // Function to create a new user
// function createUser() {
//     const email = document.getElementById('user-email').value;
//     const password = document.getElementById('user-password').value;

//     fetch('/users/', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//             'Authorization': `Bearer ${sessionStorage.getItem('auth_token')}`
//         },
//         body: JSON.stringify({ email, password })
//     })
//     .then(response => response.json())
//     .then(data => {
//         if (data.success) {
//             alert('User created successfully');
//             location.reload();
//         } else {
//             alert('Error creating user');
//         }
//     });
// }

// // Function to create a new role
// function createRole() {
//     const roleName = document.getElementById('role-name').value;
//     const permissions = document.getElementById('permissions').value.split(',');

//     fetch('/roles/', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//             'Authorization': `Bearer ${sessionStorage.getItem('auth_token')}`
//         },
//         body: JSON.stringify({ role_name: roleName, permissions })
//     })
//     .then(response => response.json())
//     .then(data => {
//         if (data.success) {
//             alert('Role created successfully');
//             location.reload();
//         } else {
//             alert('Error creating role');
//         }
//     });
// }

// // Function to handle user login
// function loginUser() {
//     const email = document.getElementById('login-email').value;
//     const password = document.getElementById('login-password').value;
//     const loginType = document.querySelector('input[name="login_type"]').value;

//     fetch('/login/', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/x-www-form-urlencoded'
//         },
//         body: new URLSearchParams({
//             'email': email,
//             'password': password,
//             'login_type': loginType
//         })
//     })
//     .then(response => response.json())
//     .then(data => {
//         if (response.ok) {
//             const accessToken = data.access_token;
//             const refreshToken = data.refresh_token;

//             // Store tokens in sessionStorage
//             sessionStorage.setItem('auth_token', accessToken);
//             sessionStorage.setItem('refresh_token', refreshToken);

//             // Redirect based on login type
//             window.location.href = loginType === 'admin' ? '/admin-dashboard/' : '/user-dashboard/';
//         } else {
//             alert('Login failed: ' + (data.error || 'Unknown error'));
//         }
//     });
// }

// // Function to handle user logout
// function logoutUser() {
//     fetch('/logout/', {
//         method: 'POST',
//         headers: {
//             'Authorization': `Bearer ${sessionStorage.getItem('auth_token')}`,
//             'Content-Type': 'application/json',
//             'X-CSRFToken': getCookie('csrftoken') // Add CSRF token here
//         }
//     })
//     .then(response => {
//         if (response.ok) {
//             // Clear tokens from session storage
//             sessionStorage.removeItem('auth_token');
//             sessionStorage.removeItem('refresh_token');
            
//             // Handle cross-tab logout
//             localStorage.setItem('logout-event', 'logout' + Math.random());
//             localStorage.removeItem('logout-event');
            
//             // Redirect to the home page
//             window.location.href = '';
//         } else {
//             alert('Error logging out. Please try again.');
//         }
//     })
//     .catch(error => {
//         console.error('Error:', error);
//         alert('Error logging out. Please try again.');
//     });
// }

// // Listen for logout event across tabs
// window.addEventListener('storage', function(event) {
//     if (event.key === 'logout-event') {
//         window.location.href = '';
//     }
// });

// // Utility function to get the CSRF token from cookies
// function getCookie(name) {
//     let cookieValue = null;
//     if (document.cookie && document.cookie !== '') {
//         const cookies = document.cookie.split(';');
//         for (let i = 0; i < cookies.length; i++) {
//             const cookie = cookies[i].trim();
//             if (cookie.substring(0, name.length + 1) === (name + '=')) {
//                 cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
//                 break;
//             }
//         }
//     }
//     return cookieValue;
// }
