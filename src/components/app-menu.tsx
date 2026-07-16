import { useEffect, useRef, useState } from "react";
import { LayoutDashboard, History, ShieldAlert, BookOpen, Database, FileDown, UserCog, LogOut, Lock, KeyRound, MonitorSmartphone, Activity, Brain, Radio, Flame, Camera, Trash2 } from "lucide-react";
import { Link } from "@tanstack/react-router";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export type ViewKey = "dashboard" | "history" | "certin" | "tips" | "privacy";

const PHOTO_KEY = (email: string) => `mg.profile.photo.${email.toLowerCase()}`;
const MAX_PHOTO_BYTES = 2 * 1024 * 1024;

function initialsOf(name: string) {
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map((p) => p[0]?.toUpperCase() ?? "").join("") || "U";
}

export function AppMenu({
  username, email, onNavigate, onExportCSV, onExportPDF,
  onSwitch, onSignOut, onLockNow, onChangePasscode,
}: {
  username: string; email: string;
  onNavigate: (v: ViewKey) => void;
  onExportCSV: () => void; onExportPDF: () => void;
  onSwitch: () => void; onSignOut: () => void;
  onLockNow: () => void; onChangePasscode: () => void;
}) {
  const [photo, setPhoto] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    try { setPhoto(localStorage.getItem(PHOTO_KEY(email))); } catch { /* ignore */ }
  }, [email]);

  function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    if (!f.type.startsWith("image/")) { alert("Please choose an image file."); return; }
    if (f.size > MAX_PHOTO_BYTES) { alert("Image must be under 2 MB."); return; }
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result || "");
      try { localStorage.setItem(PHOTO_KEY(email), dataUrl); } catch { /* quota */ }
      setPhoto(dataUrl);
    };
    reader.readAsDataURL(f);
  }

  function removePhoto() {
    try { localStorage.removeItem(PHOTO_KEY(email)); } catch { /* ignore */ }
    setPhoto(null);
  }

  return (
    <>
      <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={onPick} />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            aria-label="Open profile menu"
            className="relative h-10 w-10 rounded-full overflow-hidden border border-border ring-1 ring-transparent hover:ring-primary/40 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            style={{ background: photo ? undefined : "linear-gradient(135deg, oklch(0.30 0.06 200), oklch(0.22 0.04 260))" }}
          >
            {photo ? (
              <img src={photo} alt={username} className="h-full w-full object-cover" />
            ) : (
              <span className="flex h-full w-full items-center justify-center text-sm font-semibold text-foreground/90">
                {initialsOf(username)}
              </span>
            )}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-72 bg-card border-border">
          <DropdownMenuLabel className="font-normal">
            <div className="flex items-center gap-3">
              <div className="relative h-12 w-12 rounded-full overflow-hidden border border-border shrink-0"
                   style={{ background: photo ? undefined : "linear-gradient(135deg, oklch(0.30 0.06 200), oklch(0.22 0.04 260))" }}>
                {photo ? (
                  <img src={photo} alt="" className="h-full w-full object-cover" />
                ) : (
                  <span className="flex h-full w-full items-center justify-center text-sm font-semibold">
                    {initialsOf(username)}
                  </span>
                )}
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold truncate">{username}</div>
                <div className="text-[11px] text-muted-foreground font-mono truncate">{email}</div>
                <div className="flex gap-3 mt-1">
                  <button className="text-[11px] text-primary hover:underline inline-flex items-center gap-1"
                          onClick={(e) => { e.preventDefault(); fileRef.current?.click(); }}>
                    <Camera className="h-3 w-3" /> {photo ? "Change" : "Add"} photo
                  </button>
                  {photo && (
                    <button className="text-[11px] text-muted-foreground hover:text-destructive inline-flex items-center gap-1"
                            onClick={(e) => { e.preventDefault(); removePhoto(); }}>
                      <Trash2 className="h-3 w-3" /> Remove
                    </button>
                  )}
                </div>
              </div>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => onNavigate("dashboard")}><LayoutDashboard className="h-4 w-4" /> Dashboard</DropdownMenuItem>
          <DropdownMenuItem onClick={() => onNavigate("history")}><History className="h-4 w-4" /> Mail history</DropdownMenuItem>
          <DropdownMenuItem asChild><Link to="/devices"><MonitorSmartphone className="h-4 w-4" /> Trusted devices</Link></DropdownMenuItem>
          <DropdownMenuItem asChild><Link to="/timeline"><Activity className="h-4 w-4" /> Security timeline</Link></DropdownMenuItem>
          <DropdownMenuItem asChild><Link to="/advisories"><Radio className="h-4 w-4" /> Live CERT-In advisories</Link></DropdownMenuItem>
          <DropdownMenuItem asChild><Link to="/threats"><Flame className="h-4 w-4" /> Top 6 threats · 2025/26</Link></DropdownMenuItem>
          <DropdownMenuItem asChild><Link to="/quiz"><Brain className="h-4 w-4" /> Awareness quiz & simulator</Link></DropdownMenuItem>
          <DropdownMenuItem onClick={() => onNavigate("certin")}><ShieldAlert className="h-4 w-4" /> India CERT-In</DropdownMenuItem>
          <DropdownMenuItem onClick={() => onNavigate("tips")}><BookOpen className="h-4 w-4" /> Security tips</DropdownMenuItem>
          <DropdownMenuItem onClick={() => onNavigate("privacy")}><Database className="h-4 w-4" /> Data & privacy</DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={onExportCSV}><FileDown className="h-4 w-4" /> Export history (CSV)</DropdownMenuItem>
          <DropdownMenuItem onClick={onExportPDF}><FileDown className="h-4 w-4" /> Export history (PDF)</DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={onChangePasscode}><KeyRound className="h-4 w-4" /> Change password</DropdownMenuItem>
          <DropdownMenuItem onClick={onLockNow}><Lock className="h-4 w-4" /> Lock now</DropdownMenuItem>
          <DropdownMenuItem onClick={onSwitch}><UserCog className="h-4 w-4" /> Switch account</DropdownMenuItem>
          <DropdownMenuItem onClick={onSignOut}><LogOut className="h-4 w-4" /> Sign out</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
