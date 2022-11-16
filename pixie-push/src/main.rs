use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{ensure, Context, Result};
use clap::Parser;
use gpt::{self};
use reqwest::{blocking::Client, Url};

use pixie_shared::{ChunkHash, Offset, Segment};

const CHUNK_SIZE: usize = 1 << 22;

#[derive(Parser, Debug)]
struct Options {
    #[clap(short, long, value_parser)]
    destination: String,
    #[clap(last = true, value_parser)]
    sources: Vec<String>,
}

trait FileSaver {
    fn save_chunk(&self, data: &[u8]) -> Result<ChunkHash>;
    fn save_image(&self, info: Vec<pixie_shared::File>) -> Result<()>;
}

#[derive(Debug)]
struct ChunkInfo {
    start: Offset,
    size: usize,
}

struct LocalFileSaver {
    path: String,
}

impl LocalFileSaver {
    fn get_chunk_path(path: &str) -> PathBuf {
        Path::new(path).join("chunks")
    }

    fn chunk_path(&self) -> PathBuf {
        LocalFileSaver::get_chunk_path(&self.path)
    }

    fn new(path: &str) -> Result<LocalFileSaver> {
        std::fs::create_dir_all(LocalFileSaver::get_chunk_path(path))?;
        Ok(LocalFileSaver {
            path: path.to_owned(),
        })
    }
}

impl FileSaver for LocalFileSaver {
    fn save_chunk(&self, data: &[u8]) -> Result<ChunkHash> {
        let hash = blake3::hash(data);
        std::fs::write(self.chunk_path().join(hash.to_hex().as_str()), data)?;
        Ok(hash.as_bytes().to_owned())
    }

    fn save_image(&self, info: Vec<pixie_shared::File>) -> Result<()> {
        let info_path = Path::new(&self.path).join("info");
        std::fs::write(info_path, serde_json::to_string(&info)?)?;
        Ok(())
    }
}

struct RemoteFileSaver {
    url: String,
}

impl RemoteFileSaver {
    fn new(url: String) -> Self {
        Self { url }
    }
}

impl FileSaver for RemoteFileSaver {
    fn save_chunk(&self, data: &[u8]) -> Result<ChunkHash> {
        let url = Url::parse(&self.url)?.join("/chunk")?;
        let client = Client::new();
        let resp = client
            .post(url)
            .body(data.to_owned())
            .send()
            .with_context(|| {
                format!(
                    "failed to upload chunk to server, chunk size {}",
                    data.len()
                )
            })?;
        ensure!(
            resp.status().is_success(),
            "failed to upload chunk to server, status {}, chunk size {}",
            resp.status().as_u16(),
            data.len()
        );
        let hash = blake3::hash(data);
        Ok(hash.as_bytes().to_owned())
    }

    fn save_image(&self, info: Vec<pixie_shared::File>) -> Result<()> {
        let client = Client::new();
        let data = serde_json::to_string(&info)?;
        let resp = client
            .post(&self.url)
            .body(data)
            .send()
            .context("failed to upload image to server")?;
        ensure!(
            resp.status().is_success(),
            "failed to upload image to server, status ({})",
            resp.status().as_u16(),
        );
        Ok(())
    }
}

fn get_ext4_chunks(path: &str) -> Result<Option<Vec<ChunkInfo>>> {
    let child = Command::new("dumpe2fs")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.unwrap();
    let mut lines = BufReader::new(stdout).lines();

    let block_size: usize = loop {
        let line = match lines.next() {
            Some(Ok(x)) => x,
            Some(Err(e)) => return Err(e.into()),
            None => return Ok(None),
        };

        if let Some(value) = line.strip_prefix("Block size:") {
            break value.trim().parse().unwrap();
        }
    };

    let mut ans = Vec::new();

    while lines.next().unwrap()? != "" {}

    loop {
        let (mut begin, end): (usize, usize) = loop {
            let line = match lines.next() {
                Some(Ok(x)) => x,
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(Some(ans)),
            };

            if let Some(s) = line.strip_prefix("Group") {
                let a = s.find('(').unwrap();
                let b = s.find('-').unwrap();
                let c = s.find(')').unwrap();
                break (
                    s[a + 8..b].parse().unwrap(),
                    s[b + 1..c].parse::<usize>().unwrap() + 1,
                );
            }
        };

        loop {
            let line = lines.next().unwrap()?;

            if let Some(s) = line.strip_prefix("  Free blocks: ") {
                if !s.is_empty() {
                    for x in s.split(", ") {
                        let (a, b) = if let Some(m) = x.find('-') {
                            let a: usize = x[..m].parse().unwrap();
                            let b: usize = x[m + 1..].parse().unwrap();
                            (a, b + 1)
                        } else {
                            let a = x.parse().unwrap();
                            (a, a + 1)
                        };

                        if begin < a {
                            ans.push(ChunkInfo {
                                start: block_size * begin,
                                size: block_size * (a - begin),
                            });
                        }
                        begin = b;
                    }
                }
                if begin < end {
                    ans.push(ChunkInfo {
                        start: block_size * begin,
                        size: block_size * (end - begin),
                    });
                }
                break;
            }
        }
    }
}

fn get_disk_chunks(path: &str) -> Result<Option<Vec<ChunkInfo>>> {
    let disk_size = {
        File::open(path)
            .expect("File cannot be opened")
            .seek(SeekFrom::End(0))
            .expect("failed to seek disk") as usize
    };
    let cfg = gpt::GptConfig::new().writable(false);
    let disk = cfg.open(path);
    if disk.is_err() {
        return Ok(None);
    }
    let disk = disk.unwrap();
    let mut pos = 0usize;
    let mut ans = vec![];
    for (id, partition) in disk.partitions().iter().enumerate() {
        let name = format!("{path}p{}", id + 1);
        // lba 512 byte
        let begin = (partition.1.first_lba * 512) as usize;
        let end = ((partition.1.last_lba + 1) * 512) as usize;

        if pos < begin {
            ans.push(ChunkInfo {
                start: pos,
                size: (begin - pos),
            });
        }

        if let Some(chunks) = get_ext4_chunks(&name)? {
            for ChunkInfo { start, size } in chunks {
                ans.push(ChunkInfo {
                    start: start + begin,
                    size,
                });
            }
        } else {
            ans.push(ChunkInfo {
                start: begin,
                size: (end - begin),
            });
        }

        pos = end;
    }

    if pos < disk_size {
        ans.push(ChunkInfo {
            start: pos,
            size: disk_size - pos,
        });
    }

    Ok(Some(ans))
}

fn get_file_chunks(path: &str) -> Result<Vec<ChunkInfo>> {
    let chunks = {
        let disk_chunks = get_disk_chunks(path)?;
        if let Some(chunks) = disk_chunks {
            chunks
        } else {
            let ext4_chunks = get_ext4_chunks(path)?;
            if let Some(chunks) = ext4_chunks {
                chunks
            } else {
                let mut file = File::open(path)?;
                let size = file.seek(SeekFrom::End(0))? as usize;
                let start = 0;
                vec![ChunkInfo { start, size }]
            }
        }
    };

    let mut out = Vec::<ChunkInfo>::new();
    for ChunkInfo { mut start, size } in chunks {
        let end = start + size;

        if let Some(last) = out.last() {
            if last.start + last.size == start {
                start = last.start;
                out.pop();
            }
        }

        while start < end {
            out.push(ChunkInfo {
                start,
                size: CHUNK_SIZE.min(end - start),
            });
            start += CHUNK_SIZE;
        }
    }

    Ok(out)
}

fn main() -> Result<()> {
    let args = Options::parse();

    ensure!(!args.sources.is_empty(), "Specify at least one source");
    ensure!(!args.destination.is_empty(), "Specify a destination");

    let file_saver: Box<dyn FileSaver> =
        if args.destination.starts_with("http://") || args.destination.starts_with("https://") {
            Box::new(RemoteFileSaver::new(args.destination))
        } else {
            Box::new(LocalFileSaver::new(&args.destination)?)
        };

    let mut stdout = io::stdout().lock();

    let mut info = Vec::new();

    // TODO(veluca): parallelize.
    for s in args.sources {
        let chunks = get_file_chunks(&s)?;

        let total_size: usize = chunks.iter().map(|x| x.size).sum();
        println!("Total size: {}", total_size);

        let mut file = std::fs::File::open(&s)?;

        let total = chunks.len();

        let chunks: Result<Vec<_>> = chunks
            .into_iter()
            .enumerate()
            .map(|(idx, chnk)| {
                write!(
                    stdout,
                    " pushing chunk {idx} out of {total} from file '{s}'\r"
                )?;
                stdout.flush()?;

                file.seek(SeekFrom::Start(chnk.start as u64))?;
                let mut data = vec![0; chnk.size];
                file.read_exact(&mut data)?;
                let hash = file_saver.save_chunk(&data)?;
                Ok(Segment {
                    hash,
                    start: chnk.start,
                    size: chnk.size,
                })
            })
            .collect();
        writeln!(stdout)?;

        info.push(pixie_shared::File {
            name: Path::new(&s).to_owned(),
            chunks: chunks?,
        });
    }

    file_saver.save_image(info)
}
