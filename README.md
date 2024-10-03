# TaskListDriver

**TaskListDriver** is a Windows kernel-mode driver that retrieves the list of currently running processes and outputs the process names along with their process IDs (PIDs) to the kernel debugger using `DbgPrint`. This driver leverages the `ZwQuerySystemInformation` API to gather system process information.

## Features

- Retrieves a list of all running processes in the system.
- Outputs each process name and its corresponding process ID (PID) to the kernel debugger.
- Uses the `DbgPrint` function to log information for easy viewing via a kernel debugger or tools like Sysinternals' DbgView.

## Prerequisites

- Windows Driver Kit (WDK)
- A kernel debugger such as WinDbg or Sysinternals' [DbgView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview)
- A test environment for deploying and testing kernel-mode drivers

## Installation and Usage

1. Build the driver using the Windows Driver Kit (WDK).
2. Load the driver into the kernel using a tool like `sc.exe` or `Devcon.exe`.
3. Start capturing debug output with either:
   - **WinDbg** attached to the target machine.
   - **DbgView** running on the target machine to capture kernel-level debug messages.
4. Observe the process names and their PIDs in the debug output.

## Code Highlights

- The driver utilizes the `ZwQuerySystemInformation` API to query process information.
- Memory for storing process information is dynamically allocated using `ExAllocatePoolWithTag`.
- Process information is logged using `DbgPrint` for easy viewing via a kernel debugger.

## Key Functions

- `DriverEntry`: The entry point of the driver. It retrieves process information and outputs the process name and PID.
- `ZwQuerySystemInformation`: A native API used to query system process details.
- `DbgPrint`: Logs the process information to the debugger console.

## Debugging

To view the output:

- **WinDbg**: Connect to the target system and view the output in the kernel debugger.
- **DbgView**: Run on the target machine to capture `DbgPrint` output in real-time.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
