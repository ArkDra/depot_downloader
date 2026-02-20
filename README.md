# Depot Downloader

Depot Downloader is a Rust-based CLI tool for downloading Steam depot content.

## Features
- Asynchronous download pipeline with concurrent decode/write workers
- Automatic CDN discovery with optional manual CDN override
- Multi-format chunk support (LZMA, Zstd, ZIP)
- Integrity checks during resume and chunk decode
- Command-line interface with proxy, retry, and file filtering controls

## Build

Release build:

```bash
cargo build --release
```

The compiled binary will be located in the `target/release` directory.

## Usage

```bash
depot_downloader [OPTIONS] [COMMAND]
```

### Basic

```bash
depot_downloader -m 123456_1234567890.manifest -k <64_hex_chars>
```

### With proxy/output/retry

```bash
depot_downloader -m 123456_1234567890.manifest -k <64_hex_chars> -o output_directory -r 3 -p http://127.0.0.1:1080
```

### Download selected files

```bash
depot_downloader -m 123456_1234567890.manifest -k <64_hex_chars> -f bin/game.exe,data/config.json
```

### Use manual CDN hosts and suffixes

```bash
depot_downloader -m 123456_1234567890.manifest -k <64_hex_chars> cdn -u steampipe.akamaized.net,fastly.cdn.steampipe.steamcontent.com -s /token_a,/token_b
```

## Options

- `-m, --manifest-path <MANIFEST_PATH>`: Manifest file path. Required.
- `-k, --depot-key <DEPOT_KEY>`: Depot decryption key as lowercase hex (AES-256 key, typically 64 hex chars). Required.
- `-o, --output-path <OUTPUT_PATH>`: Output directory. Default is `<current_dir>/<depot_id>/<file_name>`.
- `-p, --proxy-url <PROXY_URL>`: HTTP/HTTPS proxy URL.
- `-r, --retry-num <RETRY_NUM>`: Retry count per chunk.
- `-f, --file-names <FILE_NAMES>`: Comma-separated file paths to download selectively.

Subcommand `cdn`:

- `-u, --cdn-url <CDN_URL>`: Comma-separated CDN host list.
- `-s, --cdn-url-suffix <CDN_URL_SUFFIX>`: Comma-separated URL suffix list.

## License

depot_downloader is licensed under the MIT License or Apache License, Version 2.0.
