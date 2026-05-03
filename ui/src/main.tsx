import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App.tsx";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("#root element missing in index.html");

// Router basename matches the server's PATH_PREFIX so all <Link>s and
// useNavigate() targets resolve under /security without each page knowing it.
ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <BrowserRouter basename="/security">
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
