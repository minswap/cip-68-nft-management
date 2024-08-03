use aiken/list
use aiken/pairs
use aiken/transaction.{
  InlineDatum, Input, Output, ScriptContext, Spend, Transaction,
}
use aiken/transaction/credential.{Address, VerificationKeyCredential}
use aiken/transaction/value

type Asset {
  policy_id: ByteArray,
  asset_name: ByteArray,
}

type Extra {
  // Who has able to spend the UTxO that is holding CIP-68 Reference NFT  
  address: Address,
  // CIP-68 Reference NFT  
  nft: Asset,
}

// Followed by CIP-68 Metadata standard: https://github.com/cardano-foundation/CIPs/tree/master/CIP-0068
type ValidatorDatum {
  metadata: Pairs<ByteArray, Data>,
  version: Int,
  extra: Extra,
}

validator {
  // Validate spend the UTxO that is holding CIP-68 Reference NFT
  // This function is almost used for updating Token Metadata
  fn spend(datum: ValidatorDatum, _redeemer: Data, ctx: ScriptContext) -> Bool {
    let ScriptContext { transaction, purpose } = ctx
    expect Spend(out_ref) = purpose
    let Transaction { extra_signatories, inputs, outputs, .. } = transaction
    expect Some(own_input) =
      inputs |> list.find(fn(input) { input.output_reference == out_ref })

    let Input {
      output: Output { address: own_address, value: own_val, .. },
      ..
    } = own_input

    // Validate UTxO has to hold the Reference NFT
    let has_nft_in_input =
      value.quantity_of(
        own_val,
        datum.extra.nft.policy_id,
        datum.extra.nft.asset_name,
      ) == 1
    // Extract the Public Key Hash of UTxO's owner
    // TODO: Consider to support other types of Address such as Native Script and Plutus Script Address
    expect Address { payment_credential: VerificationKeyCredential(pkh), .. } =
      datum.extra.address
    // Transaction has to be signed by the UTxO's owner
    let has_signed = list.has(extra_signatories, pkh)

    // In order to prevent burning or transfering the Reference NFT, the NFT has to be paid back to new Contract's UTxO 
    expect Some(own_output_hold_nft) =
      outputs
        |> list.find(fn(out) { and {
                out.address.payment_credential == own_address.payment_credential,
                value.quantity_of(
                  out.value,
                  datum.extra.nft.policy_id,
                  datum.extra.nft.asset_name,
                ) == 1,
              } })
    expect Output { datum: InlineDatum(out_datum_raw), .. } =
      own_output_hold_nft
    expect out_datum: ValidatorDatum = out_datum_raw
    and {
      // Validate UTxO has to hold the Reference NFT
      has_nft_in_input,
      // Transaction has to be signed by the UTxO's owner
      has_signed,
      // Reference NFT has to be the same in both input & output datum
      datum.extra.nft == out_datum.extra.nft,
      validate_token_decimal(out_datum.metadata),
    }
  }
}

// Zero decimals make the token become a non-division token 
// This is not best practise in DeFi world, then contract do not allow updating decimals to zero  
fn validate_token_decimal(metadata: Pairs<ByteArray, Data>) -> Bool {
  expect Some(decimals_data) = metadata |> pairs.get_first(#"646563696d616c73")
  expect decimals: Int = decimals_data
  decimals > 0
}
