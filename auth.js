(() => {
  const login = async (email, password) => {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) return { ok: false };
    return { ok: true, ...(await res.json()) };
  };

  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
  };

  const isAuthed = async () => {
    const res = await fetch("/api/auth/me");
    if (!res.ok) return { ok: false };
    const data = await res.json();
    return { ok: true, user: data.user };
  };

  const requireAuth = async () => {
    const status = await isAuthed();
    if (!status.ok) {
      window.location.href = "login.html";
    }
  };

  window.EKAuth = { login, logout, isAuthed, requireAuth };
})();
