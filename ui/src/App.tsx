import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout.tsx";
import { Home } from "./pages/Home.tsx";
import { Hosts } from "./pages/Hosts.tsx";
import { Host } from "./pages/Host.tsx";
import { Login } from "./pages/Login.tsx";
import { Project } from "./pages/Project.tsx";
import { Findings } from "./pages/Findings.tsx";
import { api, type SessionUser } from "./api.ts";

type AuthState =
  | { kind: "loading" }
  | { kind: "anon" }
  | { kind: "user"; user: SessionUser };

export function App(): JSX.Element {
  const [auth, setAuth] = useState<AuthState>({ kind: "loading" });

  useEffect(() => {
    api
      .me()
      .then((res) =>
        setAuth(res.kind === "user" ? { kind: "user", user: res.user } : { kind: "anon" }),
      )
      .catch(() => setAuth({ kind: "anon" }));
  }, []);

  if (auth.kind === "loading") {
    return <div className="loading">Loading…</div>;
  }

  if (auth.kind === "anon") {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Layout user={auth.user} onLogout={async () => {
      await api.logout();
      setAuth({ kind: "anon" });
    }}>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/projects/:name" element={<Project />} />
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/hosts/:name" element={<Host />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/login" element={<Navigate to="/" replace />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  );
}

function NotFound(): JSX.Element {
  return (
    <div className="empty">
      <h2>Not found</h2>
      <p>That page doesn't exist.</p>
    </div>
  );
}
