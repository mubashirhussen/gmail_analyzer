import { Menu, LayoutDashboard, History, ShieldAlert, BookOpen, Database, FileDown, UserCog, LogOut } from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export type ViewKey = "dashboard" | "history" | "certin" | "tips" | "privacy";

export function AppMenu({
  username, email, onNavigate, onExportCSV, onExportPDF, onSwitch, onSignOut,
}: {
  username: string; email: string;
  onNavigate: (v: ViewKey) => void;
  onExportCSV: () => void; onExportPDF: () => void;
  onSwitch: () => void; onSignOut: () => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="inline-flex items-center gap-2 rounded-md border border-border px-2.5 py-1.5 text-xs font-mono hover:bg-accent">
          <Menu className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">{username}</span>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60 bg-card border-border">
        <DropdownMenuLabel className="font-normal">
          <div className="text-sm font-semibold">{username}</div>
          <div className="text-[11px] text-muted-foreground font-mono truncate">{email}</div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => onNavigate("dashboard")}><LayoutDashboard className="h-4 w-4" /> Dashboard</DropdownMenuItem>
        <DropdownMenuItem onClick={() => onNavigate("history")}><History className="h-4 w-4" /> Mail history</DropdownMenuItem>
        <DropdownMenuItem onClick={() => onNavigate("certin")}><ShieldAlert className="h-4 w-4" /> India CERT-In</DropdownMenuItem>
        <DropdownMenuItem onClick={() => onNavigate("tips")}><BookOpen className="h-4 w-4" /> Security tips</DropdownMenuItem>
        <DropdownMenuItem onClick={() => onNavigate("privacy")}><Database className="h-4 w-4" /> Data & privacy</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={onExportCSV}><FileDown className="h-4 w-4" /> Export history (CSV)</DropdownMenuItem>
        <DropdownMenuItem onClick={onExportPDF}><FileDown className="h-4 w-4" /> Export history (PDF)</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={onSwitch}><UserCog className="h-4 w-4" /> Switch / add account</DropdownMenuItem>
        <DropdownMenuItem onClick={onSignOut}><LogOut className="h-4 w-4" /> Sign out</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
