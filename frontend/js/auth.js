document.addEventListener('DOMContentLoaded', async () => {
    // Check if already logged in
    try {
        await API.me();
        window.location.href = 'dashboard.html';
        return;
    } catch (e) {
        // Not logged in, stay on page
    }

    // Tab switching
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');
        });
    });

    // Login Form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const errorDiv = document.getElementById('login-error');
        
        try {
            await API.login(email, password);
            window.location.href = 'dashboard.html';
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
        }
    });

    // Register Form
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;
        const errorDiv = document.getElementById('register-error');
        
        if (password !== confirm) {
            errorDiv.textContent = "Passwords do not match";
            errorDiv.style.display = 'block';
            return;
        }

        try {
            await API.register(email, password);
            window.location.href = 'dashboard.html';
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.style.display = 'block';
        }
    });
});

function togglePasswordVisibility(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function fillDemoCredentials() {
    const email = document.getElementById('login-email');
    const pass = document.getElementById('login-password');
    if (email) email.value = 'demo@veloshield.internal';
    if (pass) pass.value = 'VeloShieldDemo2026!';
}

