# lsassDumper

`LsassDumper` is a utility designed to dump the Local Security Authority Subsystem Service (LSASS) process memory to a file. This can be useful for security analysis or debugging purposes.

## Features

- **Enable Debug Privilege**: Automatically enables the `SE_DEBUG_NAME` privilege required to access LSASS.
- **Modify LSA Protection**: Temporarily disables LSA protection to allow for dumping.
- **Admin Check**: Ensures the program is run with administrative privileges.
- **Dump LSASS**: Dumps the LSASS process memory to a specified file.
- **Restore LSA Protection**: Re-enables LSA protection after dumping.

## Usage

To use `LsassDumper`, follow these steps:

## Build Instructions
1. Clone the repository
```bash
git clone https://github.com/mendax0110/lsassDumper.git
```

2. Change directory to the cloned repository
```bash
cd lsassDumper
```

3. Create the build directory
```bash
mkdir build
```

4. Change directory to the build directory
```bash
cd build
```

5. Build CMake files
```bash
cmake ..
```

6. Build the project
```bash
cmake --build .
```

## Usage
```bash
lsassDumper.exe -p <dump file path>
```

## Supported Platforms
- Windows