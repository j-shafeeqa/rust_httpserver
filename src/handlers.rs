use axum::{Json, response::Json as ResponseJson};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer, Signature},
    system_instruction,
};
use spl_token::{
    instruction::{initialize_mint, mint_to, transfer},
};
use std::str::FromStr;
use base64::prelude::*;

use crate::{
    error::Result,
    models::*,
};

/// Generate a new Solana keypair
pub async fn generate_keypair() -> Result<ResponseJson<ApiResponse<KeypairResponse>>> {
    tracing::info!("Generating new keypair");
    
    let keypair = Keypair::new();
    
    // Encode public key as base58
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    
    // Encode secret key as base58
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    let response = KeypairResponse { pubkey, secret };
    
    tracing::info!("Keypair generated successfully");
    Ok(ResponseJson(ApiResponse::success(response)))
}

/// Create SPL token mint instruction
pub async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>> {
    tracing::info!("Creating token mint instruction");
    
    // Parse the mint authority public key
    let mint_authority = Pubkey::from_str(&payload.mint_authority)
        .map_err(|e| anyhow::anyhow!("Invalid mint authority public key: {}", e))?;
    
    // Parse the mint public key
    let mint = Pubkey::from_str(&payload.mint)
        .map_err(|e| anyhow::anyhow!("Invalid mint public key: {}", e))?;
    
    // Validate decimals (SPL tokens support 0-255 decimals, but typically 0-18)
    if payload.decimals > 18 {
        return Err(anyhow::anyhow!("Decimals should not exceed 18").into());
    }
    
    // Create the initialize mint instruction
    let instruction = initialize_mint(
        &spl_token::ID,
        &mint,
        &mint_authority,
        Some(&mint_authority), // freeze authority (same as mint authority)
        payload.decimals,
    )?;
    
    // Convert instruction to our response format
    let accounts: Vec<AccountMeta> = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let instruction_data = BASE64_STANDARD.encode(&instruction.data);
    
    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    tracing::info!("Token mint instruction created successfully");
    Ok(ResponseJson(ApiResponse::success(response)))
}

/// Create mint-to instruction for SPL tokens
pub async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>> {
    tracing::info!("Creating mint-to instruction");
    
    // Parse the mint public key
    let mint = Pubkey::from_str(&payload.mint)
        .map_err(|e| anyhow::anyhow!("Invalid mint public key: {}", e))?;
    
    // Parse the destination public key
    let destination = Pubkey::from_str(&payload.destination)
        .map_err(|e| anyhow::anyhow!("Invalid destination public key: {}", e))?;
    
    // Parse the authority public key
    let authority = Pubkey::from_str(&payload.authority)
        .map_err(|e| anyhow::anyhow!("Invalid authority public key: {}", e))?;
    
    // Validate amount
    if payload.amount == 0 {
        return Err(anyhow::anyhow!("Amount must be greater than 0").into());
    }
    
    // Create the mint-to instruction
    let instruction = mint_to(
        &spl_token::ID,
        &mint,
        &destination,
        &authority,
        &[],  // No additional signers
        payload.amount,
    )?;
    
    // Convert instruction to our response format
    let accounts: Vec<AccountMeta> = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let instruction_data = BASE64_STANDARD.encode(&instruction.data);
    
    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    tracing::info!("Mint-to instruction created successfully");
    Ok(ResponseJson(ApiResponse::success(response)))
}

/// Sign a message using a private key
pub async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageResponse>>> {
    tracing::info!("Signing message");
    
    // Decode the secret key from base58
    let secret_bytes = bs58::decode(&payload.secret)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("Invalid secret key format: {}", e))?;
    
    if secret_bytes.len() != 64 {
        return Err(anyhow::anyhow!("Invalid secret key length").into());
    }
    
    // Create keypair from secret key
    let keypair = Keypair::from_bytes(&secret_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
    
    // Sign the message
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    let response = SignMessageResponse {
        signature: BASE64_STANDARD.encode(signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
        message: payload.message,
    };
    
    tracing::info!("Message signed successfully");
    Ok(ResponseJson(ApiResponse::success(response)))
}

/// Verify a signed message
pub async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageResponse>>> {
    tracing::info!("Verifying message signature");
    
    // Parse the public key
    let pubkey = Pubkey::from_str(&payload.pubkey)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
    
    // Decode the signature from base64
    let signature_bytes = BASE64_STANDARD.decode(&payload.signature)
        .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;
    
    if signature_bytes.len() != 64 {
        return Err(anyhow::anyhow!("Invalid signature length").into());
    }
    
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;
    
    // Verify the signature
    let message_bytes = payload.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);
    
    let response = VerifyMessageResponse {
        valid: is_valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };
    
    tracing::info!("Message verification completed");
    Ok(ResponseJson(ApiResponse::success(response)))
}

/// Create a SOL transfer instruction
pub async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<SolTransferResponse>>> {
    tracing::info!("Creating SOL transfer instruction");
    
    // Parse the from address
    let from_pubkey = Pubkey::from_str(&payload.from)
        .map_err(|e| anyhow::anyhow!("Invalid from address: {}", e))?;
    
    // Parse the to address
    let to_pubkey = Pubkey::from_str(&payload.to)
        .map_err(|e| anyhow::anyhow!("Invalid to address: {}", e))?;
    
    // Validate lamports amount
    if payload.lamports == 0 {
        return Err(anyhow::anyhow!("Amount must be greater than 0").into());
    }
    
    // Create the transfer instruction
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);
    
    // Convert instruction to SOL transfer response format (array of account addresses)
    let accounts: Vec<String> = instruction
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();
    
    let instruction_data = BASE64_STANDARD.encode(&instruction.data);
    
    let response = SolTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    tracing::info!("SOL transfer instruction created successfully");
    Ok(ResponseJson(ApiResponse::success(response)))
}

/// Create an SPL token transfer instruction
pub async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>> {
    tracing::info!("Creating SPL token transfer instruction");
    
    // Parse the mint address (for validation)
    let _mint = Pubkey::from_str(&payload.mint)
        .map_err(|e| anyhow::anyhow!("Invalid mint address: {}", e))?;
    
    // Parse the destination address
    let destination = Pubkey::from_str(&payload.destination)
        .map_err(|e| anyhow::anyhow!("Invalid destination address: {}", e))?;
    
    // Parse the owner address
    let owner = Pubkey::from_str(&payload.owner)
        .map_err(|e| anyhow::anyhow!("Invalid owner address: {}", e))?;
    
    // Validate amount
    if payload.amount == 0 {
        return Err(anyhow::anyhow!("Amount must be greater than 0").into());
    }
    
    // Create the token transfer instruction
    let instruction = transfer(
        &spl_token::ID,
        &owner,        // source account (owner's token account)
        &destination,  // destination token account
        &owner,        // owner authority
        &[],          // no additional signers
        payload.amount,
    )?;
    
    // Convert instruction to our response format
    let accounts: Vec<AccountMeta> = instruction
        .accounts
        .iter()
        .map(|acc| AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let instruction_data = BASE64_STANDARD.encode(&instruction.data);
    
    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    tracing::info!("SPL token transfer instruction created successfully");
    Ok(ResponseJson(ApiResponse::success(response)))
}

