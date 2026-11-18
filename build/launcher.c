// RemoteDesk.exe: avvia runtime\pythonw.exe app\remotedesk.py con gli stessi argomenti.
#include <windows.h>
#include <wchar.h>
int WINAPI wWinMain(HINSTANCE h, HINSTANCE p, LPWSTR args, int show) {
    wchar_t dir[MAX_PATH], cmd[32768];
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    wchar_t *s = wcsrchr(dir, L'\\'); if (s) *s = 0;
    _snwprintf(cmd, 32768, L"\"%s\\runtime\\pythonw.exe\" \"%s\\app\\remotedesk.py\" %s", dir, dir, args ? args : L"");
    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
        MessageBoxW(NULL, L"Impossibile avviare RemoteDesk: cartella runtime mancante o danneggiata.", L"RemoteDesk", MB_ICONERROR);
        return 1;
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
