import { Link } from "react-router-dom";
import type { SessionUser } from "../api.ts";

interface Props {
  user: SessionUser;
  onLogout: () => void;
  children: React.ReactNode;
}

export function Layout({ user, onLogout, children }: Props): JSX.Element {
  return (
    <div className="app">
      <header className="topbar">
        <Link to="/" className="brand">agent-security</Link>
        <nav className="navlinks">
          <Link to="/">Projects</Link>
          <Link to="/findings">Findings</Link>
        </nav>
        <div className="user">
          <span title={user.email}>{user.name}</span>
          <button type="button" onClick={onLogout} className="linkbtn">
            Sign out
          </button>
        </div>
      </header>
      <main className="content">{children}</main>
    </div>
  );
}
