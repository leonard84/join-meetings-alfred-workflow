extern crate chrono;
extern crate clap;
extern crate dirs;
extern crate google_calendar3 as calendar3;
extern crate hyper;
extern crate hyper_rustls;
extern crate itertools;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate time;
extern crate yup_oauth2 as oauth2;

use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;

use alfred::Item;
use calendar3::CalendarHub;
use chrono::prelude::*;
use clap::App;
use clap::Arg;
use clap::ArgMatches;
use clap::SubCommand;
use hyper::net::HttpsConnector;
use hyper::Client;
use itertools::Itertools;
use oauth2::read_application_secret;
use oauth2::AuthenticatorDelegate;
use oauth2::ConsoleApplicationSecret;
use oauth2::DiskTokenStorage;
use oauth2::FlowType;
use oauth2::GetToken;
use oauth2::Token;
use oauth2::{Authenticator, DefaultAuthenticatorDelegate};
use regex::Regex;
use time::Duration;

fn main() {
    let app = create_app_config();
    let cli_args = app.get_matches();

    let result = perform_cli_action(cli_args);
    alfred::json::write_items(io::stdout(), result.as_slice()).unwrap();
}

fn create_app_config<'a>() -> App<'a, 'a> {
    App::new("Zoom Alfred Workflow")
        .subcommand(
            SubCommand::with_name("code")
                .arg(Arg::with_name("code").help("The OAuth 2.0 verification code from Google.")),
        )
        .arg(Arg::with_name("search").multiple(true))
}

fn perform_cli_action<'a>(cli_args: ArgMatches) -> Vec<Item<'a>> {
    let app_home = dirs::home_dir().unwrap().join(".zoom-alfred-workflow");
    if !app_home.exists() {
        fs::create_dir_all(&app_home).unwrap();
    };

    let token_path = app_home.join("tokens");
    let token_path_string = token_path.to_str().unwrap().to_string();

    let mut items = Vec::new();

    match read_secret(app_home.join("client_secret.json").as_path()) {
        Err(_) => {
            items.push(alfred::ItemBuilder::new("~/.zoom-alfred-workflow/client_secret.json not found")
                .subtitle("Follow this guide on creating client credentials")
                .arg("https://developers.google.com/youtube/registering_an_application#Create_OAuth2_Tokens")
                .into_item());
            items.push(
                alfred::ItemBuilder::new("Or go to the Google Developer Console directly")
                    .arg("https://console.developers.google.com/apis/credentials")
                    .into_item(),
            );
            items.push(
                alfred::ItemBuilder::new("Finally, download the json file")
                    .subtitle("to ~/.zoom-alfred-workflow/client_secret.json")
                    .into_item(),
            );
        }
        Ok(secret) => {
            if !token_path.exists() {
                let action = determine_permission_action(cli_args);
                items.append(permission_flow(action, secret, &token_path_string).as_mut());
            } else {
                let search = if let Some(matches) = cli_args.values_of("search") {
                    matches.into_iter().join(" ")
                } else {
                    String::new()
                };
                items.append(main_flow(secret, &token_path_string, search).as_mut())
            }
        }
    };

    return items;
}

fn determine_permission_action(matches: ArgMatches) -> PermissionAction {
    if let Some(matches) = matches.subcommand_matches("code") {
        if let Some(code) = matches.value_of("code") {
            return PermissionAction::UserEnteredCode(String::from(code));
        } else {
            return PermissionAction::UserShouldEnterCode;
        }
    }
    return PermissionAction::ShowVerificationURL;
}

enum PermissionAction {
    ShowVerificationURL,
    UserShouldEnterCode,
    UserEnteredCode(String),
}

fn read_secret(path: &Path) -> io::Result<ConsoleApplicationSecret> {
    let secret = read_application_secret(path)?;
    Ok(ConsoleApplicationSecret {
        web: None,
        installed: Some(secret),
    })
}

fn new_client() -> Client {
    return Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new()));
}

fn extract_zoom_link(txt: String) -> Option<String> {
    lazy_static! {
        static ref ZM_RE: Regex = Regex::new(
            r"https?://(?P<server>.*?zoom\.us)/j/(?P<code>[0-9]+)(?:\?pwd=(?P<pwd>\w+))?"
        )
        .unwrap();
        static ref GM_RE: Regex =
            Regex::new(r"(https://meet.google.com/[a-z0-9-]+(?:\?authuser=\w+)?)").unwrap();
    }

    let zoom = ZM_RE.captures(txt.as_str()).map(|c| {
        format!(
            "zoommtg://{}/join?action=join&confno={}{}",
            c.name("server").unwrap().as_str(),
            c.name("code").unwrap().as_str(),
            c.name("pwd")
                .map_or("".to_string(), |m| format!("&pwd={}", m.as_str()))
        )
    });
    let google_meet = GM_RE
        .captures(txt.as_str())
        .map(|c| c.get(1).unwrap().as_str().to_owned());

    return zoom.or(google_meet);
}

struct UrlExtractingAuthenticatorDelegate<'a> {
    verification_url: &'a mut String,
}
impl<'a> AuthenticatorDelegate for UrlExtractingAuthenticatorDelegate<'a> {
    fn present_user_url(&mut self, url: &String, _need_code: bool) -> Option<String> {
        self.verification_url.push_str(url.as_str());
        None
    }
}

struct UserProvidedCodeAuthenticatorDelegate {
    code: String,
}
impl AuthenticatorDelegate for UserProvidedCodeAuthenticatorDelegate {
    fn present_user_url(&mut self, _url: &String, _need_code: bool) -> Option<String> {
        Some(self.code.clone() + "\n")
    }
}

fn get_verification_url(secret: ConsoleApplicationSecret, token_file: &String) -> String {
    let mut urdel = String::from("");

    let delegate = UrlExtractingAuthenticatorDelegate {
        verification_url: &mut urdel,
    };

    let mut alfred_auth = Authenticator::new(
        &secret.installed.unwrap(),
        delegate,
        new_client(),
        DiskTokenStorage::new(token_file).unwrap(),
        Some(FlowType::InstalledInteractive),
    );
    let token = alfred_auth.token(&["https://www.googleapis.com/auth/calendar.events.readonly"]);
    assert_eq!(token.is_err(), true);
    return urdel;
}

fn verify_code(
    secret: ConsoleApplicationSecret,
    token_file: &String,
    verification_code: &String,
) -> Result<Token, Box<dyn Error>> {
    let delegate = UserProvidedCodeAuthenticatorDelegate {
        code: verification_code.clone(),
    };
    let mut alfred_auth = Authenticator::new(
        &secret.installed.unwrap(),
        delegate,
        new_client(),
        DiskTokenStorage::new(token_file).unwrap(),
        Some(FlowType::InstalledInteractive),
    );
    let token = alfred_auth.token(&["https://www.googleapis.com/auth/calendar.events.readonly"]);
    return token;
}

fn permission_flow<'a>(
    action: PermissionAction,
    secret: ConsoleApplicationSecret,
    token_file: &String,
) -> Vec<Item<'a>> {
    let mut v = Vec::new();
    match action {
        PermissionAction::ShowVerificationURL => {
            let url = get_verification_url(secret, token_file);
            v.push(
                alfred::ItemBuilder::new("1. Open Google authentication page")
                    .valid(true)
                    .arg(url)
                    .into_item(),
            );
            v.push(
                alfred::ItemBuilder::new("2. Enter Verification Code")
                    .valid(false)
                    .autocomplete("code ")
                    .into_item(),
            );
        }
        PermissionAction::UserShouldEnterCode => {
            v.push(
                alfred::ItemBuilder::new("Paste the Verification Code")
                    .valid(false)
                    .into_item(),
            );
        }
        PermissionAction::UserEnteredCode(code) => match verify_code(secret, token_file, &code) {
            Ok(_) => v.push(
                alfred::ItemBuilder::new("Tokens Stored Successfully")
                    .valid(false)
                    .into_item(),
            ),
            Err(error) => v.push(
                alfred::ItemBuilder::new(
                    String::from(error.to_string().as_str()) + " :: " + code.as_str(),
                )
                .into_item(),
            ),
        },
    }
    v
}

fn main_flow<'a>(
    secret: ConsoleApplicationSecret,
    token_file: &String,
    search: String,
) -> Vec<Item<'a>> {
    let auth = Authenticator::new(
        &secret.installed.unwrap(),
        DefaultAuthenticatorDelegate,
        new_client(),
        DiskTokenStorage::new(token_file).unwrap(),
        Some(FlowType::InstalledInteractive),
    );

    let hub = CalendarHub::new(new_client(), auth);

    let now = Utc::now();
    let tomorrow_midnight = (Utc::today() + Duration::days(2)).and_hms(0, 0, 0);

    let (_, events) = hub
        .events()
        .list("primary")
        .single_events(true)
        .time_min(now.format("%+").to_string().as_str())
        .time_max(tomorrow_midnight.format("%+").to_string().as_str())
        .order_by("starttime")
        .doit()
        .unwrap();

    let mut items: Vec<alfred::Item> = Vec::new();

    for e in events.items.unwrap() {
        let start = e
            .start
            .and_then(|dt| dt.date_time)
            .and_then(|dt| DateTime::parse_from_rfc3339(dt.as_str()).ok());
        let creator = e.creator.and_then(|c| c.display_name.or(c.email));

        let meeting_code: Option<String> = e
            .conference_data
            .into_iter()
            .flat_map(|c| c.entry_points.into_iter().flat_map(|e| e.into_iter()))
            .find_map(|e| e.uri.and_then(|u| extract_zoom_link(u)));

        let zoom = e
            .description
            .and_then(|d| extract_zoom_link(d))
            .or(e.location.and_then(|l| extract_zoom_link(l)))
            .or(meeting_code);

        let summary = e.summary.unwrap();
        if zoom.is_some() && (search.is_empty() || summary.contains(search.as_str())) {
            let today_or_tomorrow = if start.unwrap().day() == Utc::today().day() {
                "Today"
            } else {
                "Tomorrow"
            };
            let item = alfred::ItemBuilder::new(format!(
                "{} - {} at {}",
                summary,
                today_or_tomorrow,
                start.unwrap().time().format("%H:%M")
            ))
            .subtitle(creator.unwrap())
            .arg(zoom.unwrap())
            .into_item();
            items.push(item);
        }
    }
    if items.is_empty() {
        items.push(
            alfred::ItemBuilder::new("No Zoom meeting scheduled in the next 24 hours.")
                .valid(false)
                .into_item(),
        )
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zoom_meeting_with_password() {
        let txt = "Join the Zoom call:<br><a href=\"https://acme.zoom.us/j/92731537985?pwd=bGI4cxJuUDBzcm1oZGFuWEorRmsxQT09\" id=\"ow641\" __is_owner=\"true\"><span>https://acme.zoom.us/j/92731537985?pwd=bGI4cxJuUDBzcm1oZGFuWEorRmsxQT09</span></a><br><span><span>Meeting-ID: 997 3953 7985</span> </span><br><br>".to_owned();

        assert_eq!(Some("zoommtg://acme.zoom.us/join?action=join&confno=92731537985&pwd=bGI4cxJuUDBzcm1oZGFuWEorRmsxQT09".to_owned()), extract_zoom_link(txt));
    }

    #[test]
    fn test_zoom_meeting_without_password() {
        let txt = "Join the Zoom call:<br><a href=\"https://acme.zoom.us/j/92731537985\" id=\"ow641\" __is_owner=\"true\"><span>https://acme.zoom.us/j/92731537985</span></a><br><span><span>Meeting-ID: 997 3953 7985</span> </span><br><br>".to_owned();

        assert_eq!(
            Some("zoommtg://acme.zoom.us/join?action=join&confno=92731537985".to_owned()),
            extract_zoom_link(txt)
        );
    }

    #[test]
    fn test_extract_zoom_link_returns_empty_when_no_link_is_found() {
        let txt = "".to_owned();
        assert_eq!(None, extract_zoom_link(txt));
    }

    #[test]
    fn test_google_meeting() {
        let txt = "https://meet.google.com/tik-nahf-tok".to_owned();

        assert_eq!(
            Some("https://meet.google.com/tik-nahf-tok".to_owned()),
            extract_zoom_link(txt)
        );
    }

    #[ignore]
    #[test]
    // Disabled by default, since it requires a valid Google token and depends on the current calendar
    fn run_search_manually() {
        let arg_vec = vec!["search"];

        let matches = create_app_config().get_matches_from(arg_vec);
        assert_eq!(perform_cli_action(matches).len(), 0);
    }
}
