import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { clearStoredAuth, loadStoredAuth, login as apiLogin, saveStoredAuth, type StoredAuth } from "../lib/api";

interface AuthContextValue {
  auth: StoredAuth | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<StoredAuth | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    setAuth(loadStoredAuth());
    setIsLoading(false);
  }, []);

  async function login(username: string, password: string) {
    const token = await apiLogin(username, password);
    const next: StoredAuth = { token: token.access_token, username: token.username, role: token.role };
    saveStoredAuth(next);
    setAuth(next);
  }

  function logout() {
    clearStoredAuth();
    setAuth(null);
  }

  return <AuthContext.Provider value={{ auth, isLoading, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
