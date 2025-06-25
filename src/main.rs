mod manifest;
use crate::manifest::*;
use aes::{
    Aes256,
    cipher::{
        BlockDecryptMut, KeyInit, KeyIvInit, block_padding::Pkcs7, generic_array::GenericArray,
    },
};
use clap::Parser;
use data_encoding::{BASE64_MIME, HEXLOWER};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use liblzma::stream::{Action::Run, Filters, Stream};
use protobuf::Message;
use reqwest::Client;
use serde_json::Value;
use sha1_smol::Sha1;
use std::{
    fs::{self, File},
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::AsyncWriteExt,
    task::spawn_blocking,
    time::{Duration, sleep},
};
type Error = Box<dyn std::error::Error>;
#[cfg(windows)]
const INVALID_CHARS: &[char] = &['/', ':', '*', '?', '"', '<', '>', '|'];
static NEXT_URL_INDEX: AtomicUsize = AtomicUsize::new(0);

#[derive(Parser)]
struct Args {
    #[arg(short = 'm', long, required = true)]
    manifest_path: String,
    #[arg(short = 'k', long, required = true)]
    depot_key: String,
    #[arg(short = 'o', long, default_value = "default", required = false)]
    output_path: String,
    #[arg(short = 'r', long, default_value = "3", required = false)]
    retry_num: u32,
    cdn_url_list: Option<Vec<String>>,
}
impl Args {
    pub fn get_args(&self) -> (&str, &str, &str, u32, &Option<Vec<String>>) {
        (
            &self.manifest_path,
            &self.depot_key,
            &self.output_path,
            self.retry_num,
            &self.cdn_url_list,
        )
    }
}

#[derive(Clone)]
struct ChunkInfo {
    offset: u64,
    original_size: u32,
    depot_id: u32,
    file_path: PathBuf,
    content_sha: String,
}
impl ChunkInfo {
    pub fn new(
        offset: u64,
        original_size: u32,
        depot_id: u32,
        file_path: PathBuf,
        content_sha: String,
    ) -> Self {
        ChunkInfo {
            offset,
            original_size,
            depot_id,
            file_path,
            content_sha,
        }
    }

    pub async fn get_chunk(
        &self,
        steam_content_url_list: Vec<String>,
        client: &Client,
        retry_num: u32,
    ) -> Vec<u8> {
        let url_list_len = steam_content_url_list.len();
        let mut index = NEXT_URL_INDEX.fetch_add(1, Ordering::Relaxed) % url_list_len;
        let mut retry_count = 0;

        loop {
            let url = format!(
                "http://{}/depot/{}/chunk/{}",
                &steam_content_url_list[index], self.depot_id, self.content_sha
            );
            match client.get(&url).send().await {
                Ok(res) => match res.bytes().await {
                    Ok(body_data) => {
                        if body_data.len() != 0 {
                            return body_data.to_vec();
                        }
                    }
                    Err(_) => {
                        // eprintln!("Failed to read response body: {}", e);
                    }
                },
                Err(_) => {
                    // eprintln!("Request error: {}", e);
                }
            }

            retry_count += 1;
            if retry_count < retry_num {
                sleep(Duration::from_millis(200)).await;
                index = (index + 1) % url_list_len;
            } else {
                eprintln!("Max retries reached. Aborting.");
                return vec![];
            }
        }
    }

    pub async fn write_chunk_into_file(&self, decrypted_data: Vec<u8>) -> Result<(), Error> {
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)
            .await?;
        tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(self.offset)).await?;
        file.write_all(&decrypted_data).await?;
        file.flush().await?;
        Ok(())
    }
}

struct Manifest {
    manifest_content: Vec<u8>,
}
impl Manifest {
    pub fn new(manifest_path: &str) -> Self {
        let file = std::fs::File::open(manifest_path).unwrap();
        let mut bufreader = BufReader::new(file);
        let mut manifest_content = Vec::new();
        let _ = bufreader.read_to_end(&mut manifest_content);
        Manifest { manifest_content }
    }

    pub fn deserialize_manifest(
        &self,
    ) -> Result<(ContentManifestPayload, ContentManifestMetadata), Error> {
        let mut cursor = Cursor::new(&self.manifest_content);
        let mut payload_length = [0u8; 4];
        let _ = std::io::Cursor::seek(&mut cursor, SeekFrom::Start(4));
        let _ = cursor.read_exact(&mut payload_length);
        let payload_length = u32::from_le_bytes(payload_length);
        let mut payload = vec![0u8; payload_length as usize];
        let _ = cursor.read_exact(&mut payload);
        let _ = std::io::Cursor::seek(&mut cursor, SeekFrom::Current(4));
        let mut metadata_length = [0u8; 4];
        let _ = cursor.read_exact(&mut metadata_length);
        let metadata_length = u32::from_le_bytes(metadata_length);
        let mut metadata = vec![0u8; metadata_length as usize];
        let _ = cursor.read_exact(&mut metadata);
        let payload = ContentManifestPayload::parse_from_bytes(&payload)?;
        let metadata = ContentManifestMetadata::parse_from_bytes(&metadata)?;
        Ok((payload, metadata))
    }
}

struct Decrypt {
    key: Vec<u8>,
    encrypted_data: Vec<u8>,
    iv: Vec<u8>,
}
impl Decrypt {
    pub fn new(encrypted_data: Vec<u8>) -> Self {
        Decrypt {
            key: vec![],
            encrypted_data,
            iv: vec![],
        }
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = key
    }

    fn set_iv(&mut self, iv: Vec<u8>) {
        self.iv = iv
    }

    fn ecb_decrypt(&self, iv: &[u8]) -> Result<Vec<u8>, Error> {
        let key = HEXLOWER.decode(&self.key)?;
        let mut block = GenericArray::from_slice(iv).to_owned();
        let mut cipher = ecb::Decryptor::<Aes256>::new_from_slice(&key).unwrap();
        cipher.decrypt_block_mut(&mut block);
        let data = block.to_vec();
        Ok(data)
    }

    fn cbc_decrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let key = HEXLOWER.decode(&self.key)?;
        let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&key, &self.iv).unwrap();
        let _ = cipher.decrypt_padded_mut::<Pkcs7>(&mut data);
        Ok(data)
    }

    pub fn decrypt_chunk(&mut self) -> Result<Vec<u8>, Error> {
        let decrypted_iv = self.ecb_decrypt(&self.encrypted_data[..16])?;
        self.set_iv(decrypted_iv);
        let data = self.encrypted_data[16..].to_vec();
        self.encrypted_data = self.cbc_decrypt(data)?;
        let data_len = self.encrypted_data.len() as usize;
        if self.encrypted_data[..3] == [86, 90, 97]
            && data_len % 16 == 0
            && self.encrypted_data[data_len - 2..data_len] != [122, 118]
        {
            let pad_value = self.encrypted_data[data_len - 1];
            let pad_len = pad_value as usize;
            return Ok(self.encrypted_data[..data_len - pad_len].to_owned());
        }
        Ok(self.encrypted_data.to_owned())
    }

    pub fn decrypt_file_name(&mut self) -> Result<String, Error> {
        let file_name = String::from_utf8(self.decrypt_chunk()?)?;
        Ok(file_name
            .chars()
            .filter(|c| !c.is_control() && !INVALID_CHARS.contains(c))
            .collect::<String>())
    }

    pub fn decrypt_vz(&self) -> Result<Vec<u8>, Error> {
        let mut header = [0u8; 4];
        let data_header = &self.encrypted_data[..4];
        header.clone_from_slice(data_header);
        if header[..3] == [86, 90, 97] {
            let mut filter = Filters::new();
            let filter = filter.lzma1_properties(&self.encrypted_data[7..12])?;
            let raw_data = &self.encrypted_data[12..&self.encrypted_data.len() - 9];
            let mut decrypted_data = Vec::with_capacity(1048576);
            match Stream::new_raw_decoder(&filter)?.process_vec(raw_data, &mut decrypted_data, Run)
            {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("vz Error: {}", e);
                }
            }
            return Ok(decrypted_data);
        } else if header == [80, 75, 3, 4] {
            Err("vz Zip file detected".into())
        } else {
            // if &self.encrypted_data.len() ==
            let mut file = File::create("error.unknown")?;
            let _ = file.write_all(&self.encrypted_data);
            Err("vz Unknown file format detected".into())
        }
    }
}

fn set_client() -> Result<Client, Error> {
    Ok(reqwest::ClientBuilder::new()
        .use_native_tls()
        .tcp_keepalive(Duration::from_secs(20))
        .timeout(Duration::from_secs(30))
        .build()?)
}

async fn get_steam_content_url_list(client: &Client) -> Result<Vec<String>, Error> {
    let url =
        "https://api.steampowered.com/icontentserverdirectoryservice/getserversforsteampipe/v1";
    let response = client.get(url).send().await?;
    let text = &response.text().await?;
    let json_data: Value = serde_json::from_str(&text)?;
    let servers = json_data["response"]["servers"]
        .as_array()
        .ok_or("servers not found")?;

    let mut url_list = Vec::new();
    for server in servers {
        if server["weighted_load"].as_i64() <= Some(130) {
            if let Some(host) = server["host"].as_str() {
                if host.contains("steamcontent.com") {
                    url_list.push(host.to_string());
                }
            }
        }
    }
    Ok(url_list)
}

fn prepare_output_file(
    file_name: &str,
    file_sha: String,
    depot_id: u32,
    output_path: &str,
    file_size: u64,
) -> Result<(bool, PathBuf), Error> {
    let depot_id_string = depot_id.to_string();
    let path = if output_path == "default" {
        let mut path_buf = std::env::current_dir()?;
        path_buf.push(depot_id_string);
        path_buf.push(file_name);
        path_buf
    } else {
        Path::new(output_path).join(depot_id_string).join(file_name)
    };

    if path.exists() {
        let mut bufreader = BufReader::new(File::open(&path)?);
        let mut file_content = Vec::new();
        let _ = bufreader.read_to_end(&mut file_content);
        let mut hasher = Sha1::new();
        hasher.update(&file_content);
        let downloaded_file_sha = hasher.digest().to_string();
        if file_sha == downloaded_file_sha {
            println!("{} already downloaded", file_name);
            return Ok((true, path));
        }
    } else {
        if let Some(parent_dir) = path.parent() {
            if !parent_dir.exists() {
                fs::create_dir_all(parent_dir)?;
            }
        }
        let file = File::create(&path)?;
        file.set_len(file_size)?
    }
    Ok((false, path))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let (manifest_path, depot_key, output_path, retry_num, cdn_url_list) = args.get_args();

    let manifest = Manifest::new(manifest_path);
    let (payload, metadata) = Manifest::deserialize_manifest(&manifest)?;

    let depot_key = depot_key.to_owned().into_bytes();
    let client = set_client()?;

    let steam_content_url_list = match cdn_url_list {
        Some(cdn_url_list) => cdn_url_list.to_owned(),
        None => get_steam_content_url_list(&client).await?,
    };

    let cpu_num = num_cpus::get();

    for file in payload.mappings {
        if file.flags == 0 {
            let file_name = if metadata.filenames_encrypted {
                let decoded_file_name = BASE64_MIME.decode(file.filename.as_bytes())?;
                let mut decrypt = Decrypt::new(decoded_file_name);
                decrypt.set_key(depot_key.clone());
                decrypt.decrypt_file_name()?
            } else {
                file.filename
            };

            let file_sha = HEXLOWER.encode(&file.sha_content);
            let (is_exist, path) = prepare_output_file(
                &file_name,
                file_sha,
                metadata.depot_id,
                output_path,
                file.size,
            )?;
            if is_exist {
                continue;
            }

            let pb = ProgressBar::new(file.size).with_style(ProgressStyle::with_template(
                "[{elapsed_precise}] [{msg}] [{bar}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
            )?
            .progress_chars("#>-"));
            pb.set_message(file_name);

            let client_for_closure = &client;
            let steam_content_url_list_for_closure = &steam_content_url_list;
            let path_for_closure = &path;
            let pb_for_closure = &pb;

            stream::iter(file.chunks)
                .map(|chunk| async move {
                    let chunk_sha = HEXLOWER.encode(&chunk.sha);
                    let chunk_info = ChunkInfo::new(
                        chunk.offset,
                        chunk.cb_original,
                        metadata.depot_id,
                        path_for_closure.to_owned(),
                        chunk_sha.clone(),
                    );

                    let data = chunk_info
                        .get_chunk(
                            steam_content_url_list_for_closure.to_owned(),
                            &client_for_closure,
                            retry_num,
                        )
                        .await;

                    if data.len() == 0 {
                        return;
                    }

                    let decrypted_data = spawn_blocking(move || {
                        let mut decrypt = Decrypt::new(data);
                        let decrypted_data =
                            decrypt.decrypt_chunk().expect("Failed to decrypt chunk");

                        let decrypt_vz = Decrypt::new(decrypted_data);
                        let vz_data = &decrypt_vz.decrypt_vz().expect("Failed to decrypt vz")
                            [..chunk_info.original_size as usize];

                        let mut hasher = Sha1::new();
                        hasher.update(&vz_data);
                        let downloaded_chunk_sha = hasher.digest().bytes();
                        if chunk.sha == downloaded_chunk_sha {
                            Ok(vz_data.to_owned())
                        } else {
                            Err("sha dismatch")
                        }
                    })
                    .await
                    .unwrap()
                    .expect("Failed to decrypt chunk");

                    chunk_info
                        .write_chunk_into_file(decrypted_data)
                        .await
                        .expect("Failed to write chunk into file");

                    pb_for_closure.inc(chunk.cb_original.into());
                })
                .buffer_unordered(cpu_num * 4)
                .collect::<Vec<_>>()
                .await;
        }
    }

    Ok(())
}
