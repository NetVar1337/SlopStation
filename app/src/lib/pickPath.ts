// app/src/lib/pickPath.ts
// file and folder pickers: the native dialog in the app, a prompt in browser
// dev mode (no dialog plugin there)

import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { isTauri } from "@/lib/endpoint";

export async function pickSavePath(title: string, defaultPath: string): Promise<string | null> {
  if (isTauri()) return saveDialog({ title, defaultPath });
  return window.prompt(title, defaultPath);
}

export async function pickOpenPath(title: string, defaultPath: string): Promise<string | null> {
  if (isTauri()) {
    const picked = await openDialog({ title, multiple: false });
    return typeof picked === "string" ? picked : null;
  }
  return window.prompt(title, defaultPath);
}

export async function pickDirectory(title: string, defaultPath: string): Promise<string | null> {
  if (isTauri()) {
    const picked = await openDialog({ title, directory: true, multiple: false });
    return typeof picked === "string" ? picked : null;
  }
  return window.prompt(title, defaultPath);
}
