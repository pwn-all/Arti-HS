use anyhow::Result;
use arti_client::config::TorClientConfigBuilder;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use futures_util::Stream;
use safelog::DisplayRedacted;
use std::{env, sync::Arc};
use tor_config::ExplicitOrAuto::Explicit;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::{HsNickname, RunningOnionService, StreamRequest, handle_rend_requests};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_rtcompat::PreferredRuntime;

fn bootstrap_config() -> Result<TorClientConfig> {
    let mut tor_builder = TorClientConfigBuilder::default();
    let storage_builder = tor_builder.storage();
    let keystore_builder = storage_builder.keystore();
    let primary_builder = keystore_builder.primary();
    primary_builder.kind(Explicit(ArtiKeystoreKind::Ephemeral));

    Ok(tor_builder.build()?)
}

fn onion_service_config() -> Result<tor_hsservice::OnionServiceConfig> {
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(HsNickname::new("tmp".to_string())?)
        .num_intro_points(8)
        .enable_pow(true)
        .build()?;

    Ok(hs_config)
}

pub async fn init_tor_service(
    hsid: HsIdKeypair,
) -> Result<(
    TorClient<PreferredRuntime>,
    Arc<RunningOnionService>,
    impl Stream<Item = StreamRequest> + Send,
)> {
    let cfg = bootstrap_config()?;
    let tor_client = TorClient::create_bootstrapped(cfg).await?;
    let isolated_client = tor_client.isolated_client();
    let hs_config = onion_service_config()?;

    let Some((running_service, request_stream)) =
        isolated_client.launch_onion_service_with_hsid(hs_config, hsid)?
    else {
        anyhow::bail!("Hidden service disabled in config");
    };

    if let Some(addr) = running_service.onion_address() {
        if env::var("ONION_ADDR_LOG_FULL").is_ok() {
            println!(
                "ℹ️  Full onion address (ONION_ADDR_LOG_FULL set): {}",
                addr.display_unredacted()
            );
        }
    }

    let stream_requests = handle_rend_requests(request_stream);

    Ok((tor_client, running_service, stream_requests))
}
