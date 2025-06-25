# Depot Downloader

Depot Downloader is a Rust-based tool for downloading Steam depot asynchronously.

## Features
- Asynchronous downloading of Steam depot
- Efficient and scalable architecture
- Command-line interface

## Build

Clone the repository and build the project using Cargo:

```bash
cargo build --release
```

The compiled binary will be located in the `target/release` directory.

## Usage

Run the downloader from the command line:

```bash
async_depot_downloader [OPTIONS] [CDN_URL_LIST]
```

### Example

```bash
async_depot_downloader -m 123456_1234567890.manifest -k abcdef1234567890
```

or

```bash
async_depot_downloader -m 123456_1234567890.manifest -k abcdef1234567890 -o output_directory -r 3 steampipe.akamaized.net fastly.cdn.steampipe.steamcontent.com
```

#### Options
- `-m, --manifest-path <MANIFEST_PATH>`: Manifest file path (Required)
- `-k, --depot-key <DEPOT_KEY>`: Depot decryption key (Required)
- `-o, --output-path <OUTPUT_PATH>`: Output directory
- `-r, --retry-num <RETRY_NUM>`: Retry number
- Other options may be available; run with `-h` for details.

## License

This project is licensed under the MIT License or Apache License, Version 2.0.
