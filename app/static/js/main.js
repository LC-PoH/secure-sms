// app/static/js/main.js — SecureSMS UI helpers

// Password visibility toggle
document.addEventListener('DOMContentLoaded', function () {
  const toggleBtn = document.getElementById('togglePwd');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', function () {
      const field = document.getElementById('passwordField');
      const icon  = document.getElementById('eyeIcon');
      if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'bi bi-eye-slash';
      } else {
        field.type = 'password';
        icon.className = 'bi bi-eye';
      }
    });
  }
});
