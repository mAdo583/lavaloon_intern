$(document).ready(function() {
    $('#create-event-form').on('submit', function(e) {
        e.preventDefault(); // Prevent the default form submission

        // Get JWT token from localStorage or cookie
        var jwtToken = getJwtToken();

        if (!jwtToken) {
            alert("JWT token is missing. Please log in.");
            window.location.href = '/login';
            return;
        }

        $.ajax({
            url: '/event/create',
            type: 'POST',
            headers: {
                'Authorization': 'Bearer ' + jwtToken,
                'X-CSRFToken': getCsrfToken()  // Include CSRF token if applicable
            },
            data: $(this).serialize(),
            success: function(response) {
                if (response.success) {
                    window.location.href = '/home'; // Redirect to home page on success
                } else {
                    $('#response-message').text(response.message);
                }
            },
            error: function(xhr, status, error) {
                console.error("AJAX Error: ", status, error);
                if (xhr.status === 401) {
                    alert("Unauthorized: Please log in again.");
                    window.location.href = '/login'; // Redirect to login page if unauthorized
                } else if (xhr.status === 422) {
                    alert("Unprocessable Entity: There was an issue with the data submitted.");
                } else {
                    alert("An unexpected error occurred. Please try again.");
                }
            }
        });
    });

    // Function to get JWT token from localStorage or cookie
    function getJwtToken() {
        return localStorage.getItem('jwt_token') || getCookie('jwt_token');
    }

    // Function to get CSRF token from cookies
    function getCsrfToken() {
        return getCookie('csrf_token');
    }

    // Function to get cookie value by name
    function getCookie(name) {
        var cookieName = name + "=";
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = cookies[i].trim();
            if (cookie.indexOf(cookieName) === 0) {
                return cookie.substring(cookieName.length, cookie.length);
            }
        }
        return null;
    }
});
