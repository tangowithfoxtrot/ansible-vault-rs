use std::{
    collections::HashMap,
    fs::{self, File},
    io::{IsTerminal, Read, Write},
    os::unix::process::CommandExt,
    path::Path,
    process,
};

use ansible_vault::{decrypt_vault_from_file, encrypt_vault_from_file};
use anyhow::{Result, bail};
use clap::{CommandFactory, Parser, Subcommand};

/// Encryption/decryption utility for Ansible data files
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

// positional arguments:
//   {create,decrypt,edit,view,encrypt,encrypt_string,rekey}
//     create              Create new vault encrypted file
//     edit                Edit vault encrypted file
//     view                View vault encrypted file
//     encrypt_string      Encrypt a string
//     rekey               Re-key a vault encrypted file

#[derive(Subcommand)]
enum Commands {
    Create {},
    /// Generate command-line completions for your shell
    Completions {
        /// the shell to generate completions for
        shell: Option<clap_complete::Shell>,
    },
    /// Decrypt an Ansible vault-encrypted file
    Decrypt {
        encrypted_file: String,

        /// output file name for encrypt or decrypt; use - for stdout
        #[arg(long, short)]
        output: String,

        // the vault identity to use. This argument may be specified multiple times.
        /// NOT IMPLEMENTED
        #[arg(long)]
        vault_id: Option<String>,

        /// ask for vault password
        #[arg(long, short = 'J', visible_alias = "ask-vault-pass")]
        ask_vault_password: bool,

        /// vault password file(s)
        #[arg(long, visible_alias = "vault-pass-file", env = "VAULT_PASSWORD_FILES")]
        vault_password_file: Vec<String>,

        // Causes Ansible to print more debug messages. Adding multiple -v will increase the verbosity, the builtin plugins currently evaluate
        /// NOT IMPLEMENTED
        #[arg(long)]
        verbose: bool,
    },
    /// Encrypt a file
    Encrypt {
        file: String,

        /// output file name for encrypt or decrypt; use - for stdout
        #[arg(long, short)]
        output: String,

        // the vault identity to use. This argument may be specified multiple times.
        /// NOT IMPLEMENTED
        #[arg(long)]
        vault_id: Option<String>,

        /// ask for vault password
        #[arg(long, short = 'J', visible_alias = "ask-vault-pass")]
        ask_vault_password: bool,

        /// vault password file(s)
        #[arg(long, visible_alias = "vault-pass-file", env = "VAULT_PASSWORD_FILES")]
        vault_password_file: Vec<String>,

        // the vault id used to encrypt (required if more than one vault-id is provided)
        /// NOT IMPLEMENTED
        #[arg(long, env = "ENCRYPT_VAULT_ID")]
        encrypt_vault_id: Vec<String>,

        // Causes Ansible to print more debug messages. Adding multiple -v will increase the verbosity, the builtin plugins currently evaluate
        /// NOT IMPLEMENTED
        #[arg(long)]
        verbose: bool,
    },
    Run {
        encrypted_file: String,

        command: Vec<String>,

        /// output file name for encrypt or decrypt; use - for stdout
        #[arg(long, short)]
        output: String,

        // the vault identity to use. This argument may be specified multiple times.
        /// NOT IMPLEMENTED
        #[arg(long)]
        vault_id: Option<String>,

        /// ask for vault password
        #[arg(long, short = 'J', visible_alias = "ask-vault-pass")]
        ask_vault_password: bool,

        /// vault password file(s)
        #[arg(
            long,
            short,
            visible_alias = "vault-pass-file",
            env = "VAULT_PASSWORD_FILES"
        )]
        vault_password_file: Vec<String>,

        // Causes Ansible to print more debug messages. Adding multiple -v will increase the verbosity, the builtin plugins currently evaluate
        /// NOT IMPLEMENTED
        #[arg(long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        match command {
            Commands::Completions { shell } => {
                let Some(shell) = shell.or_else(clap_complete::Shell::from_env) else {
                    bail!(
                        "Couldn't automatically detect the shell. Run `a-vault completions --help` for more info."
                    );
                };

                let mut cmd = Cli::command();
                let name = cmd.get_name().to_string();
                clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            }
            Commands::Create {} => {
                bail!("NOT IMPLEMENTED");
            }
            Commands::Encrypt {
                file,
                output,
                vault_id: _,
                ask_vault_password,
                vault_password_file,
                encrypt_vault_id: _,
                verbose: _,
            } => {
                let mut encryption_password = String::new();

                if !vault_password_file.is_empty() {
                    // TODO: figure out how this is supposed to work. this is probably wrong.
                    // I haven't actually used multiple password files.
                    // TODO: support interpreting password files as scripts
                    for file in vault_password_file {
                        encryption_password = fs::read_to_string(Path::new(&file))?;
                    }
                }

                if ask_vault_password {
                    encryption_password = rpassword::prompt_password("New vault password: ")?;
                }

                let encrypted = encrypt_vault_from_file(file, &encryption_password)?;

                if output == "-" {
                    println!("{}", encrypted);
                } else {
                    let mut file = File::create(output)?;
                    file.write_all(encrypted.as_bytes())?;
                }
            }
            Commands::Decrypt {
                encrypted_file,
                output,
                vault_id: _,
                ask_vault_password,
                vault_password_file,
                verbose: _,
            } => {
                let mut decryption_password = String::new();

                if !vault_password_file.is_empty() {
                    // TODO: figure out how this is supposed to work. this is probably wrong.
                    // I haven't actually used multiple password files.
                    // TODO: support interpreting password files as scripts
                    for file in vault_password_file {
                        decryption_password = fs::read_to_string(Path::new(&file))?;
                    }
                }

                if ask_vault_password {
                    decryption_password = rpassword::prompt_password("Vault password: ")?;
                }

                let decrypted = decrypt_vault_from_file(encrypted_file, &decryption_password)?;

                if output == "-" {
                    println!("{}", String::from_utf8_lossy(&decrypted));
                } else {
                    let mut file = File::create(output)?;
                    file.write_all(&decrypted)?;
                }
            }
            Commands::Run {
                encrypted_file,
                output: _,
                vault_id: _,
                ask_vault_password,
                vault_password_file,
                verbose: _,
                command,
            } => {
                let mut decryption_password = if !vault_password_file.is_empty() {
                    let file_path = Path::new(vault_password_file[0].as_str()); // fix this to whatever you decide
                    let Ok(decryption_password) = get_password_from_file(file_path) else {
                        bail!("Couldn't get the password from the file");
                    };
                    decryption_password
                } else {
                    String::new()
                };

                if ask_vault_password {
                    decryption_password = rpassword::prompt_password("Vault password: ")?;
                }

                let decrypted = decrypt_vault_from_file(encrypted_file, &decryption_password)?;

                let kv_pairs: HashMap<String, String> = serde_yaml::from_slice(&decrypted)?;

                let user_command = if command.is_empty() {
                    if std::io::stdin().is_terminal() {
                        bail!("No command provided");
                    }

                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)?;
                    buffer
                } else {
                    command.join(" ")
                };

                let mut command =
                    // TODO: --shell arg
                    process::Command::new(std::env::var("SHELL").unwrap_or("/bin/sh".to_owned()));
                command
                    .arg("-c")
                    .arg(&user_command)
                    .envs(kv_pairs)
                    .stdout(process::Stdio::inherit())
                    .stderr(process::Stdio::inherit());

                let _ = command.exec();
            }
        };
    }
    Ok(())
}

fn get_password_from_file(file: &Path) -> std::result::Result<String, String> {
    match fs::read_to_string(file) {
        Ok(s) => Ok(s),
        Err(e) => Err(e.to_string()),
    }
}
