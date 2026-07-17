"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Code,
  BarChart3,
  Settings,
  Zap,
  CreditCard,
  Play,
  Shield,
  Fingerprint,
  BrainCircuit
} from "lucide-react";
import { cn } from "@/lib/utils";

const navigation = [
  {
    name: "Overview",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    name: "APIs",
    href: "/apis",
    icon: Code,
  },
  {
    name: "Playground",
    href: "/playground",
    icon: Play,
  },
  {
    name: "Usage",
    href: "/usage",
    icon: BarChart3,
  },
  {
    name: "Security",
    href: "/security",
    icon: Shield,
  },
  {
    name: "Threat Detection",
    href: "/anomaly",
    icon: BrainCircuit,
  },
  {
    name: "Billing",
    href: "/billing",
    icon: CreditCard,
  },
  {
    name: "Data Protection",
    href: "/data-protection",
    icon: Fingerprint,
  },
  {
    name: "Transparency",
    href: "/transparency",
    icon: Shield,
  },
  {
    name: "Settings",
    href: "/settings",
    icon: Settings,
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 border-r border-sidebar-border bg-sidebar">
      <div className="flex h-16 items-center border-b border-sidebar-border px-6">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-sidebar-primary">
            <Zap className="h-4 w-4 text-sidebar-primary-foreground" />
          </div>
          <span className="text-base font-semibold tracking-tight text-sidebar-foreground">
            GaaS Gateway
          </span>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 px-3 py-4">
        {navigation.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname?.startsWith(item.href));
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all duration-200",
                "hover:bg-sidebar-accent/50 hover:translate-x-0.5",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-sm"
                  : "text-sidebar-foreground/70 hover:text-sidebar-foreground"
              )}
            >
              <item.icon className={cn(
                "h-4 w-4 shrink-0",
                isActive ? "text-sidebar-accent-foreground" : "text-sidebar-foreground/50"
              )} />
              <span className="truncate">{item.name}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
