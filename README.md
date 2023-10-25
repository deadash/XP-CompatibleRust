# MakeXPStub: Make Your PE Executables XP-Compatible

## Introduction

`MakeXPStub` is a utility designed to make your PE (Portable Executable) files compatible with Windows XP. This is particularly useful for executables compiled with Rust, which may not natively support Windows XP. The tool operates by modifying the Import Address Table (IAT) of the target executable to forward incompatible API calls to `xpstub.dll`. This DLL contains implementations that make these APIs compatible with Windows XP. The underlying implementation for these thunks is sourced from [YY-Thunks](https://github.com/Chuyu-Team/YY-Thunks).

## Features

- **Modify PE Files**: Automatically update the IAT to make your executables XP-compatible.
- **DLL Forwarding**: Forwards incompatible API calls to `xpstub.dll`.
- **Built for Rust**: Tailored for executables compiled with Rust but can be used for any PE file.
- **Minimal Footprint**: Generates minimal patches that can be easily distributed.

## Prerequisites

- Rust Toolchain
- Windows SDK
- NMake (For building `xpstub.dll`)

## Compilation

To compile the project, you need to execute two commands:

1. Build the native components with the batch script:

   ```bash
   make.bat
   ```

2. Then build the Rust components:

   ```bash
   cargo build --release
   ```

## Usage

After the compilation steps, you can use the `makexpstub.exe` command-line utility to convert your executables. Here's the basic syntax:

```bash
makexpstub.exe --input a.exe --output a-xp.exe
```

This will read `a.exe`, modify its IAT, and produce `a-xp.exe` which will be compatible with Windows XP.

## Contributing

We welcome contributions and bug reporting. Feel free to open an issue or submit a pull request.

## Acknowledgements

A big thank you to the [YY-Thunks project](https://github.com/Chuyu-Team/YY-Thunks) for providing the essential API implementations that made this project possible.

## License

This project is licensed under [MIT License](https://chat.openai.com/c/LICENSE).

For more details, please refer to the [LICENSE](https://chat.openai.com/c/LICENSE) file in the repository.
