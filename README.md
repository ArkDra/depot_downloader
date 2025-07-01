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
depot_downloader [OPTIONS] [COMMAND]
```

### Example

```bash
depot_downloader -m 123456_1234567890.manifest -k abcdef1234567890
```

or

```bash
depot_downloader -m 123456_1234567890.manifest -k abcdef1234567890 -o output_directory -r 3 -p http://127.0.0.1:1080
```

#### Options

- `-m, --manifest-path <MANIFEST_PATH>`: Manifest file path (Required)
- `-k, --depot-key <DEPOT_KEY>`: Depot decryption key (Required)
- `-o, --output-path <OUTPUT_PATH>`: Output directory
- `-p, --proxy_url <PROXY_URL>`: Proxy URL
- `-r, --retry-num <RETRY_NUM>`: Retry number
- Other options may be available; run with `-h` for details.

#### CDN Parameters (Optional)

- `-u, --cdn-url <CDN_URL>`: CDN URL
- `-s, --cdn-suffix <CDN_SUFFIX>`: CDN URL suffix

You can specify custom CDN URLs and suffixes via subcommands, for example:

```bash
depot_downloader -m 123456_1234567890.manifest -k abcdef1234567890 cdn -u steampipe.akamaized.net,fastly.cdn.steampipe.steamcontent.com -s /suffix1,/suffix2
```

## License

This project is licensed under the MIT License or Apache License, Version 2.0.
