# IDAPro Plugins for Swift

## Installation

Run `install-plugins.sh`.

## Usage

### plugins/swift_register_args.py
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

