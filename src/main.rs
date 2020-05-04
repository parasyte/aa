use crate::vcs::{JDROCKS, VCS};
use gumdrop::Options;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};

#[cfg(feature = "random")]
use randomize::PCG32;

mod vcs;

#[derive(Debug, Options)]
struct Args {
    help: bool,

    #[options(help = "Path to write unprotected Verilog file")]
    output: Option<String>,

    #[options(free, required, help = "Path to protected Verilog file")]
    input: String,
}

fn print_pli_info(buffer: &[u8]) {
    let make_print = |c: &u8| {
        let c = *c as char;
        if c.is_ascii() && !c.is_ascii_control() {
            c
        } else {
            '.'
        }
    };

    let magic: String = buffer.iter().take(3).map(make_print).collect();
    let version = if magic.as_bytes() == JDROCKS.0 {
        "0"
    } else if magic.as_bytes() == JDROCKS.1 {
        "1"
    } else {
        "UNKNOWN"
    };
    let protected = if buffer[4] & 1 == 1 { "yes" } else { "no" };
    let last_block: String = buffer.iter().skip(0x8).take(0x8).map(make_print).collect();
    eprintln!("magic:        {}", magic);
    eprintln!("version:      {}", version);
    eprintln!("G:            {}", make_print(&buffer[3]));
    eprintln!("protected:    {}", protected);
    eprintln!("last_block:   {}", last_block);
    eprintln!("licence_code: {:?}", &buffer[0x1f..0x1f + 4]);
}

fn decrypt_line(
    file: &mut impl Write,
    vcs: &mut VCS,
    buffer: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let (decoded, length, _more) = VCS::vodka_twist(&buffer[..], buffer.len());

    // FIXME
    vcs.length = 0x30;

    vcs.buffer[..decoded.len()].copy_from_slice(&decoded);
    vcs.decipher();

    write!(file, "{}", String::from_utf8_lossy(&vcs.buffer[..length]))?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse_args_default_or_exit();

    let input = BufReader::new(File::open(args.input)?);
    let mut output: BufWriter<Box<dyn Write>> = if let Some(output) = args.output {
        BufWriter::new(Box::new(File::create(output)?))
    } else {
        BufWriter::new(Box::new(io::stdout()))
    };

    // Locate the protected section (if any)
    let mut lines = input.lines();

    // Write the non-protected head
    for line in &mut lines {
        let line = line?;
        if line == "`protected" {
            break;
        }

        writeln!(output, "{}", line)?;
    }

    // The first line contains the header
    let buffer = lines.next().expect("Unable to read protected contents")?;
    let buffer = buffer.as_bytes();

    // Decrypt and setup the cipher state
    let mut vcs = VCS::new();
    vcs.sp_mercury(&buffer[..]);
    vcs.last_block.copy_from_slice(&vcs.buffer[0x8..0x10]);

    print_pli_info(&vcs.buffer);

    // Write the very interesting protected stuff
    for line in &mut lines {
        let line = line?;
        if line == "`endprotected" {
            break;
        }

        decrypt_line(&mut output, &mut vcs, line.as_bytes())?;
    }

    // Write the non-protected tail
    for line in lines {
        let line = line?;
        writeln!(output, "{}", line)?;
    }

    Ok(())
}
