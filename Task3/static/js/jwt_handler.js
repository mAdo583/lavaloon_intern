// Function to get the JWT token from localStorage
function getJwtToken() {
    return localStorage.getItem('jwt_token');
}

// Function to store the JWT token in localStorage
function setJwtToken(token) {
    localStorage.setItem('jwt_token', token);
}

// Function to remove the JWT token from localStorage
function removeJwtToken() {
    localStorage.removeItem('jwt_token');
}

// Function to handle login (e.g., store JWT after successful login)
function handleLogin(response) {
    if (response && response.jwt_token) {
        setJwtToken(response.jwt_token);
    }
}

// Function to handle logout (e.g., remove JWT on logout)
function handleLogout() {
    removeJwtToken();
}

// Function to make authenticated requests
function makeAuthenticatedRequest(url, method, data, successCallback, errorCallback) {
    $.ajax({
        url: url,
        method: method,
        headers: {
            'Authorization': 'Bearer ' + getJwtToken() // Attach JWT to the request
        },
        data: data,
        success: function(response) {
            if (successCallback) successCallback(response);
        },
        error: function(xhr, status, error) {
            if (errorCallback) errorCallback(xhr, status, error);
        }
    });
}

// Example login function
function loginUser(email, password) {
    $.ajax({
        url: '/login',
        method: 'POST',
        data: { email: email, password: password },
        success: function(response) {
            handleLogin(response);
            window.location.href = '/home';  // Redirect to home page
        },
        error: function(xhr, status, error) {
            console.error("Login error:", error);
        }
    });
}

// Example logout function
function logoutUser() {
    $.ajax({
        url: '/logout',
        method: 'GET',
        success: function(response) {
            handleLogout();
            window.location.href = '/login';  // Redirect to login page
        },
        error: function(xhr, status, error) {
            console.error("Logout error:", error);
        }
    });
}

// Example function to create an event
function createEvent(eventData) {
    makeAuthenticatedRequest(
        '/event/create',
        'POST',
        eventData,
        function(response) {
            console.log("Event created successfully:", response);
        },
        function(xhr, status, error) {
            console.error("Error creating event:", error);
        }
    );
}
