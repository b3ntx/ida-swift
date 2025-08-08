# Swift Register Arguments Plugin

## Installation
Copy `swift_register_args.py` to your IDA Pro plugins directory:
- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- macOS, Linux: `~/.idapro/plugins/`

## Usage
1. Open a Swift binary in IDA Pro
2. Navigate to any Swift function
3. Right-click anywhere in the function (disassembly or decompiler view)
4. Select one of the new menu options:
   - "Add register X20 to function signature" (for self/this)
   - "Add register X21 to function signature" (for errors)
   - "Add register X22 to function signature" (for tasks)

The plugin will automatically:
- Convert the function to `__usercall` if needed
- Add the selected register as a parameter
- Update the decompiler view immediately

## Notes
- The plugin works with stripped binaries (no symbols required)
- Each register can only be added once per function