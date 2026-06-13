fn main() {
    generate_icons_if_needed();
    tauri_build::build()
}

fn generate_icons_if_needed() {
    let icons = [
        ("icons/32x32.png", 32u32, 32u32),
        ("icons/128x128.png", 128, 128),
        ("icons/128x128@2x.png", 256, 256),
        ("icons/icon.png", 512, 512),
    ];

    let icons_dir = std::path::Path::new("icons");
    if !icons_dir.exists() {
        std::fs::create_dir_all(icons_dir).expect("failed to create icons dir");
    }

    for (path, width, height) in icons {
        if !std::path::Path::new(path).exists() {
            let data = make_png(width, height);
            std::fs::write(path, data).expect("failed to write icon");
        }
    }
}

fn make_png(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    // IHDR: 8bpc RGBA (color_type=6)
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    write_chunk(&mut out, b"IHDR", &ihdr);

    // Scanlines: filter_byte(0) + width * RGBA(30,30,50,255)
    let row_len = 1 + (width as usize) * 4;
    let mut raw = vec![0u8; row_len * height as usize];
    for y in 0..height as usize {
        let base = y * row_len;
        for x in 0..width as usize {
            let p = base + 1 + x * 4;
            raw[p] = 30;
            raw[p + 1] = 30;
            raw[p + 2] = 50;
            raw[p + 3] = 255;
        }
    }

    let idat = zlib_store(&raw);
    write_chunk(&mut out, b"IDAT", &idat);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

fn write_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    let mut combined = Vec::with_capacity(4 + data.len());
    combined.extend_from_slice(tag);
    combined.extend_from_slice(data);
    out.extend_from_slice(&crc32(&combined).to_be_bytes());
}

// zlib header + uncompressed deflate stored blocks + Adler-32 trailer
fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // CMF=0x78, FLG=0x01: (0x78 * 256 + 0x01) % 31 == 0
    out.extend_from_slice(&[0x78, 0x01]);

    const MAX_BLOCK: usize = 65535;
    let mut pos = 0;
    loop {
        let end = (pos + MAX_BLOCK).min(data.len());
        let is_last = end == data.len();
        out.push(is_last as u8); // BFINAL | BTYPE=00 (stored)
        let len = (end - pos) as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&data[pos..end]);
        pos = end;
        if is_last {
            break;
        }
    }

    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    let (mut s1, mut s2) = (1u32, 0u32);
    for &b in data {
        s1 = (s1 + b as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    (s2 << 16) | s1
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}
