// Login form validation and button management
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.querySelector('form');
    const loginBtn = document.getElementById('loginBtn');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const btnText = loginBtn.querySelector('.btn-text');
    const btnSpinner = loginBtn.querySelector('.btn-spinner');

    // Function to check if all inputs are filled
    function validateForm() {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        
        if (username && password) {
            loginBtn.disabled = false;
            loginBtn.classList.remove('btn-disabled');
        } else {
            loginBtn.disabled = true;
            loginBtn.classList.add('btn-disabled');
        }
    }

    // Add event listeners to inputs
    usernameInput.addEventListener('input', validateForm);
    passwordInput.addEventListener('input', validateForm);
    usernameInput.addEventListener('blur', validateForm);
    passwordInput.addEventListener('blur', validateForm);

    // Initial validation check
    validateForm();

    // Handle form submission
    loginForm.addEventListener('submit', function(e) {
        // Check if button is already disabled (submitting)
        if (loginBtn.disabled && !loginBtn.classList.contains('btn-disabled')) {
            e.preventDefault();
            return;
        }

        // Validate before submitting
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (!username || !password) {
            e.preventDefault();
            return;
        }

        // Disable button and show spinner
        loginBtn.disabled = true;
        btnText.classList.add('d-none');
        btnSpinner.classList.remove('d-none');
        
        // DO NOT disable inputs - they need to submit their values
    });

    // Re-enable form if there's an error (page reload with errors)
    if (loginForm.querySelector('.text-danger')) {
        loginBtn.disabled = false;
        btnText.classList.remove('d-none');
        btnSpinner.classList.add('d-none');
        validateForm();
    }
});