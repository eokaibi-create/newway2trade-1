(() => {
  const form = document.querySelector("#loginForm");
  const error = document.querySelector("#loginError");

  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const user = document.querySelector("#loginUser").value.trim();
    const pass = document.querySelector("#loginPass").value;

    const ok = window.EKAuth && (await window.EKAuth.login(user, pass));
    if (ok && ok.ok) {
      error.classList.remove("show");
      window.location.href = "admin.html";
      return;
    }

    error.classList.add("show");
  });
})();
