import { loginUrl } from "../api.ts";

export function Login(): JSX.Element {
  return (
    <div className="login">
      <h1>agent-security</h1>
      <p>Sign in with Google to view security findings across projects.</p>
      <a className="btn" href={loginUrl}>Sign in with Google</a>
      <p className="muted">
        Access is restricted to allowlisted accounts. Machine clients (Jira,
        ticketing scripts) authenticate with bearer tokens instead — see
        <code> npm run cli -- token create</code>.
      </p>
    </div>
  );
}
