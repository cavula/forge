import type { ReactNode } from "react";
export const metadata = { title: "Forge", description: "Self-hosted IaC orchestration" };
export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
