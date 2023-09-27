#include <windows.h>
#include <fstream>

// Variáveis globais para armazenar os handles dos controles
HWND hEdit;
HWND hButtonOn;
HWND hButtonOff;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    const wchar_t CLASS_NAME[] = L"Sample Window Class";

    WNDCLASS wc = { };

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 128));  // Azul escuro

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"EDR Interface",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (hwnd == NULL)
    {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    DWORD process_id = 0;

    switch (uMsg)
    {
    case WM_CREATE:
    {
        hEdit = CreateWindow(
            L"EDIT",
            L"Obtendo IDs dos processos...",
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            0, 0, 0, 0,  // Tamanho e posição serão definidos em WM_SIZE
            hwnd,
            (HMENU)3,
            (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            NULL
        );

        hButtonOn = CreateWindow(
            L"BUTTON",
            L"Ligar",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            0, 0, 0, 0,  // Tamanho e posição serão definidos em WM_SIZE
            hwnd,
            (HMENU)1,
            (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            NULL
        );

        hButtonOff = CreateWindow(
            L"BUTTON",
            L"Desligar",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            0, 0, 0, 0,  // Tamanho e posição serão definidos em WM_SIZE
            hwnd,
            (HMENU)2,
            (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            NULL
        );

        break;
    }
    case WM_SIZE:
    {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        MoveWindow(hEdit, width / 8, height / 8, width * 3 / 4, height / 4, TRUE);
        MoveWindow(hButtonOn, width / 4, height * 5 / 8, width / 8, height / 8, TRUE);
        MoveWindow(hButtonOff, width * 5 / 8, height * 5 / 8, width / 8, height / 8, TRUE);

        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1)
        {
            MessageBox(hwnd, L"Iniciado!", L"Aviso", MB_OK);

            // Start the Console Application and store its PID
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = L"open";
            sei.lpFile = L"Injector.exe";
            sei.nShow = SW_SHOWDEFAULT;
            ShellExecuteEx(&sei);

            if (sei.hProcess != NULL)
            {
                process_id = GetProcessId(sei.hProcess);
            }


            // Set a timer to read the "logs.txt" file every 2 seconds
            SetTimer(hwnd, 1, 2000, NULL);
        }
        else if (LOWORD(wParam) == 2)
        {
            MessageBox(hwnd, L"Finalizado!", L"Aviso", MB_OK);

            // Stop the Console Application
            if (process_id != 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, process_id);
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }

            // Kill the timer
            KillTimer(hwnd, 1);
        }
        break;
    case WM_TIMER:
        // Read the "logs.txt" file
        std::ifstream file("logs.txt");
        std::string process_info((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Replace '\n' with '\r\n'
        size_t pos = 0;
        while ((pos = process_info.find('\n', pos)) != std::string::npos) {
            process_info.replace(pos, 1, "\r\n");
            pos += 2;
        }

        // Convert the process info to a wide string
        std::wstring w_process_info(process_info.begin(), process_info.end());

        // Update the edit control
        SetWindowText(hEdit, w_process_info.c_str());
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
