use super::*;

#[test]
fn formats_epoch_timestamps_for_people_and_paths() {
    assert_eq!(format_epoch_utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(format_epoch_iso_utc(1_786_502_345), "2026-08-12T02:39:05Z");
    assert_eq!(
        format_epoch_millis_filename_utc(1_786_502_345_678),
        "2026-08-12_02-39-05-678_UTC"
    );
}

#[test]
fn parses_jadx_classes_methods_and_network_context() {
    let source = r#"
            package com.example.internal;
            public final class ApiClient {
                public void configure(WebView webView) {
                    webView.getSettings().setJavaScriptEnabled(true);
                    webView.addJavascriptInterface(new Bridge(), "native");
                }

                public String request() {
                    return new Retrofit.Builder().baseUrl("https://internal.example/api/").build().toString();
                }
            }
        "#;
    let mut insights = Vec::new();
    scan_android_source(
        source,
        "jadx:sources/com/example/internal/ApiClient.java",
        &mut insights,
    );
    assert!(insights.iter().any(|item| item.kind == "android-class"
        && item.class_name.as_deref() == Some("com.example.internal.ApiClient")));
    assert!(insights
        .iter()
        .any(|item| item.kind == "android-webview-entry"
            && item.name == "configure"
            && item
                .references
                .iter()
                .any(|value| value.contains("JavaScript bridge"))));
    assert!(insights
        .iter()
        .any(|item| item.kind == "android-network-entry"
            && item.name == "request"
            && item
                .references
                .iter()
                .any(|value| value.contains("https://internal.example"))));
}

#[test]
fn parses_otool_objective_c_classes_methods_and_imp_addresses() {
    let output = r#"sample:
Contents of (__DATA,__objc_classlist) section
000000010024ec88 0x100281a28
    isa        0x100281a50
    superclass 0x0 _OBJC_CLASS_$_UIResponder
    cache      0x0 __objc_empty_cache
    data       0x100251350
        flags          0x194 RO_HAS_CXX_STRUCTORS
        name           0x10022682a AppDelegate
        baseMethods    0x10027a2c0
            entsize 24
            count   2
            name    0x1001f2895 loginBySchemeApp:
            types   0x10022d28e v20@0:8B16
            imp     0x1001c6fd4
            name    0x1001ec0d1 URLSession:didReceiveChallenge:completionHandler:
            types   0x10022d195 v24@0:8@16
            imp     0x1001c6fe4
        baseProtocols  0x0
Meta Class
    isa        0x0 _OBJC_METACLASS_$_NSObject
    superclass 0x0 _OBJC_METACLASS_$_UIResponder
    data       0x10024f738
        flags          0x195 RO_META
        name           0x10022682a AppDelegate
        baseMethods    0x10027a300
            entsize 24
            count   1
            name    0x1001f0543 sharedDelegate
            types   0x10022d1db @16@0:8
            imp     0x1001c7000
        baseProtocols  0x0
"#;
    let insights = parse_otool_objc(output, "Payload/App.app/App");
    assert!(insights
        .iter()
        .any(|item| item.kind == "ios-objc-class"
            && item.class_name.as_deref() == Some("AppDelegate")));
    let tls = insights
        .iter()
        .find(|item| item.name.contains("didReceiveChallenge"))
        .expect("TLS Objective-C method");
    assert_eq!(tls.kind, "ios-tls-entry");
    assert_eq!(tls.address.as_deref(), Some("0x1001c6fe4"));
    assert_eq!(tls.module_offset.as_deref(), Some("0x1c6fe4"));
    assert!(tls
        .runtime_target
        .as_deref()
        .is_some_and(|value| value.contains("ObjC.classes")));
    assert!(insights
        .iter()
        .any(|item| item.name == "+ sharedDelegate"
            && item.address.as_deref() == Some("0x1001c7000")));
}

#[test]
fn parses_ios_codeprotect_filter_offsets() {
    let insights = parse_ios_codeprotect_filter(
        br#"{"a":[{"f":2422664,"t":2597472}],"b":[{"f":2423376,"t":2597528}]}"#,
        "Payload/Test.app/IPACodeProtectTwoSDk_arm64_filter.json",
        Some("Test"),
    );
    assert_eq!(insights.len(), 2);
    assert_eq!(insights[0].kind, "ios-codeprotect-map");
    assert_eq!(insights[0].module_offset.as_deref(), Some("0x24f788"));
    assert!(insights[0]
        .references
        .iter()
        .any(|value| value == "target module+0x27a260"));
    assert!(insights[0]
        .runtime_target
        .as_deref()
        .is_some_and(|value| value.contains("getModuleByName(\"Test\")")));
}

#[tokio::test]
async fn extracts_real_ios_code_when_sample_is_configured() {
    let Ok(path) = std::env::var("ME_IOS_MACHO_SAMPLE") else {
        return;
    };
    let insights = analyze_ios_macho_code(Path::new(&path), "sample")
        .await
        .expect("extract Objective-C metadata and disassembly");
    let classes = insights
        .iter()
        .filter(|item| item.kind == "ios-objc-class")
        .count();
    let methods = insights
        .iter()
        .filter(|item| item.kind.starts_with("ios-") && item.name.starts_with(['-', '+']))
        .count();
    let disassembled = insights
        .iter()
        .filter(|item| !item.snippet.is_empty())
        .count();
    println!("classes={classes} methods={methods} disassembled={disassembled}");
    assert!(classes > 20, "only recovered {classes} classes");
    assert!(methods > 50, "only recovered {methods} methods");
    assert!(
        disassembled > 20,
        "only recovered {disassembled} disassembly snippets"
    );
}

#[tokio::test]
async fn analyzes_real_ipa_code_when_sample_is_configured() {
    let Ok(path) = std::env::var("ME_APP_ANALYSIS_SAMPLE") else {
        return;
    };
    let analysis = analyze_app(AnalyzeAppRequest {
        path,
        apktool_path: None,
        jadx_path: None,
        excluded_url_patterns: Vec::new(),
    })
    .await
    .expect("analyze sample IPA/APK");
    let mut code_by_binary: HashMap<&str, usize> = HashMap::new();
    for item in &analysis.code_insights {
        *code_by_binary.entry(&item.binary).or_default() += 1;
    }
    let mut code_by_binary: Vec<_> = code_by_binary.into_iter().collect();
    code_by_binary.sort_by(|left, right| right.1.cmp(&left.1));
    let mut binary_by_category: HashMap<&str, usize> = HashMap::new();
    for item in &analysis.binary_insights {
        *binary_by_category.entry(&item.category).or_default() += 1;
    }
    let mut binary_by_category: Vec<_> = binary_by_category.into_iter().collect();
    binary_by_category.sort_by(|left, right| right.1.cmp(&left.1));
    println!(
            "platform={} package={:?} frameworks={:?} libraries={:?} code={} binary={} sensitive={} code_by_binary={:?} binary_by_category={:?}",
            analysis.platform,
            analysis.package_id,
            analysis.frameworks,
            analysis.third_party_libraries,
            analysis.code_insights.len(),
            analysis.binary_insights.len(),
            analysis.sensitive_items.len(),
            code_by_binary,
            binary_by_category
        );
    assert_eq!(analysis.platform, "ios");
    assert!(analysis.code_insights.len() > 1000);
    assert!(analysis.code_insights.iter().any(|item| {
        item.class_name.as_deref() == Some("AppDelegate") && item.address.is_some()
    }));
    assert!(analysis
        .tools_used
        .iter()
        .any(|tool| tool.contains("Objective-C metadata")));
    let complete_private_keys = analysis
        .sensitive_items
        .iter()
        .filter(|item| {
            item.kind == "private-key"
                && item.value.as_deref().is_some_and(|value| {
                    value.len() > 240
                        && value.contains("-----END ")
                        && value.contains("PRIVATE KEY-----")
                })
        })
        .count();
    println!("complete_private_keys={complete_private_keys}");
    assert!(
        complete_private_keys > 0,
        "sample did not retain a complete PEM private key"
    );
    if let Ok(output_path) = std::env::var("ME_EXPORT_ANALYSIS_HTML_COMPACT") {
        let written = export_analysis_html_compact(analysis, output_path, None, None)
            .expect("export compact analysis HTML");
        println!("exported_compact_html={written}");
    } else if let Ok(output_path) = std::env::var("ME_EXPORT_ANALYSIS_HTML") {
        let written =
            export_analysis_html(analysis, output_path, None, None).expect("export analysis HTML");
        println!("exported_html={written}");
    }
}

#[test]
fn packaged_app_restores_login_shell_tools_when_configured() {
    if std::env::var("ME_TEST_PACKAGED_PATH").is_err() {
        return;
    }
    std::env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    let restored = initialize_host_environment(None).expect("restore packaged app PATH");
    assert!(restored.contains(".pyenv/shims") || restored.contains("/usr/local/bin"));
    assert!(executable_path("frida").is_some(), "{restored}");
    assert!(executable_path("frida-ps").is_some(), "{restored}");
}

#[test]
fn decodes_axml_sample_when_configured() {
    let Ok(path) = std::env::var("ME_AXML_SAMPLE") else {
        return;
    };
    let bytes = fs::read(path).expect("read AXML sample");
    let xml = decode_axml(&bytes).expect("decode binary AndroidManifest.xml");
    assert!(xml.contains("<manifest"));
    assert!(xml.contains("<uses-permission"));
    assert!(xml.contains("<activity"));
    assert!(xml.contains("android:name="));
    assert!(
        xml.lines()
            .filter(|line| line.trim().starts_with("<uses-permission"))
            .count()
            > 2
    );
    assert!(
        xml.lines()
            .filter(|line| line.trim().starts_with("<activity"))
            .count()
            > 2
    );
    assert!(
        xml.lines()
            .filter(|line| line.trim().starts_with("<uses-permission"))
            .filter_map(|line| parse_quoted_value(line, "android:name="))
            .count()
            > 2
    );
    assert!(
        xml.lines()
            .filter(|line| line.trim().starts_with("<activity"))
            .filter_map(|line| parse_quoted_value(line, "android:name="))
            .count()
            > 2
    );
    if xml.to_ascii_lowercase().contains("com.stub.stubapp") {
        let rule_set = rules::load_rules(None).expect("load protection rules");
        let mut protection = assess_protection(&[], &rule_set);
        enrich_protection_from_manifest(&xml, &mut protection, &rule_set);
        assert!(protection
            .packers
            .iter()
            .any(|value| value.contains("StubApp")));
    }
}

#[test]
fn quoted_values_keep_spaces_inside_quotes() {
    assert_eq!(
        parse_quoted_value("application-label:'My Secure App'", "application-label:"),
        Some("My Secure App".into())
    );
    assert_eq!(
        parse_quoted_value(
            r#"android:label="My Secure App" android:debuggable="false""#,
            "android:label="
        ),
        Some("My Secure App".into())
    );
}

#[test]
fn axml_string_pool_cursor_skips_style_data() {
    let mut bytes = vec![0u8; 40];
    bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&28u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&40u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&40u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&[1, 1, b'a', 0]);
    let (strings, next_chunk) = axml_string_pool(&bytes).expect("decode string pool");
    assert_eq!(strings, vec!["a"]);
    assert_eq!(next_chunk, 40);
}

#[test]
fn sensitive_patterns_compile_and_keep_context() {
    let rule_set = rules::load_rules(None).expect("load external rules");
    assert_eq!(sensitive_patterns(&rule_set).len(), 21);
    let mut items = Vec::new();
    scan_sensitive_text(
            "before\nconst api = \"https://api.corp.internal/v1\";\nconst docs = \"https://developer.android.com/reference\";\nafter",
            "Sample.java",
            &mut items,
        );
    assert!(items
        .iter()
        .any(|item| item.kind == "url"
            && item.value.as_deref() == Some("https://api.corp.internal/v1")));
    assert!(items.iter().any(|item| item.filtered
        && item
            .value
            .as_deref()
            .is_some_and(|value| value.contains("developer.android.com"))));
    assert!(items.iter().any(|item| item
        .context
        .as_deref()
        .unwrap_or_default()
        .contains("const api")));
}

#[test]
fn sensitive_scanner_keeps_complete_pem_private_key_blocks() {
    for label in [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ] {
        let body = "A".repeat(640);
        let pem = format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----");
        let input = format!("prefix\n{pem}\nsuffix");
        let mut items = Vec::new();
        scan_sensitive_text(&input, "Config.pem", &mut items);
        let item = items
            .iter()
            .find(|item| item.kind == "private-key")
            .expect("private key finding");
        assert_eq!(item.item, "私钥内容（完整 PEM）");
        assert_eq!(item.value.as_deref(), Some(pem.as_str()));
        assert!(item.value.as_ref().is_some_and(|value| value.len() > 240));
        assert!(item
            .value
            .as_deref()
            .unwrap_or_default()
            .contains(&format!("-----END {label}-----")));
    }
}

#[test]
fn sensitive_scanner_bounds_malformed_pem_and_html_redacts_complete_key() {
    let body = "B".repeat(MAX_PEM_PRIVATE_KEY_BYTES + 128);
    let malformed =
        format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
    let mut malformed_items = Vec::new();
    scan_sensitive_text(&malformed, "oversized.pem", &mut malformed_items);
    let malformed_item = malformed_items
        .iter()
        .find(|item| item.kind == "private-key")
        .expect("marker finding");
    assert_eq!(
        malformed_item.value.as_deref(),
        Some("-----BEGIN RSA PRIVATE KEY-----")
    );

    let pem = "-----BEGIN PRIVATE KEY-----\nVERY_SECRET_TEST_MATERIAL\n-----END PRIVATE KEY-----";
    let item = SensitiveItem {
        item: "私钥内容（完整 PEM）".into(),
        location: "Config.pem".into(),
        kind: "private-key".into(),
        severity: "high".into(),
        value: Some(pem.into()),
        line_number: Some(1),
        context: None,
        source: "text-resource".into(),
        filtered: false,
        filter_reason: None,
    };
    let html = render_sensitive_report_rows(&[item]);
    assert!(html.contains("原文未写入 HTML"));
    assert!(html.contains("SHA-256"));
    assert!(!html.contains("VERY_SECRET_TEST_MATERIAL"));
}

#[test]
fn static_tool_resolver_prefers_jadx_cli_over_gui_launcher() {
    let root = std::env::temp_dir().join(format!("mobilee-jadx-cli-test-{}", now_millis()));
    let bin = root.join("bin");
    fs::create_dir_all(&bin).expect("create jadx bin");
    let gui = bin.join("jadx-gui");
    let cli = bin.join("jadx");
    fs::write(&gui, "gui").expect("write gui marker");
    fs::write(&cli, "cli").expect("write cli marker");
    let resolved = resolve_static_cli_path(&gui, "jadx").expect("resolve jadx cli");
    assert_eq!(resolved, fs::canonicalize(&cli).expect("canonical cli"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn static_tool_resolver_accepts_tool_directories() {
    let root = std::env::temp_dir().join(format!("mobilee-apktool-cli-test-{}", now_millis()));
    fs::create_dir_all(&root).expect("create apktool directory");
    let cli = root.join("apktool.jar");
    fs::write(&cli, "jar").expect("write apktool marker");
    let resolved = resolve_static_cli_path(&root, "apktool").expect("resolve apktool cli");
    assert_eq!(resolved, fs::canonicalize(&cli).expect("canonical cli"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn exports_sensitive_value_with_private_permissions() {
    let destination = std::env::temp_dir().join(format!("me-private-key-{}.pem", now_millis()));
    let pem = "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----";
    let written = export_sensitive_value(ExportSensitiveValueRequest {
        value: pem.into(),
        output_path: destination.to_string_lossy().into_owned(),
    })
    .expect("export sensitive value");
    assert_eq!(
        fs::read_to_string(&written).expect("read exported value"),
        pem
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&written)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let _ = fs::remove_file(destination);
}

#[test]
fn sensitive_scanner_rejects_symbol_asset_and_version_false_positives() {
    let mut credentials = Vec::new();
    scan_sensitive_text(
        "Password: swizzleActionWithTitleMethod\nPassword: showText",
        "Symbols.txt",
        &mut credentials,
    );
    assert!(credentials
        .iter()
        .filter(|item| item.kind == "credential")
        .all(|item| item.filtered));

    let mut version = Vec::new();
    scan_sensitive_text("framework version 1.2.3.4", "Podspec.txt", &mut version);
    assert!(version
        .iter()
        .filter(|item| item.kind == "ip")
        .all(|item| item.filtered));

    let mut network = Vec::new();
    scan_sensitive_text(
        "server=10.20.30.40\ncontact=security@corp.example.net",
        "Config.txt",
        &mut network,
    );
    assert!(network
        .iter()
        .any(|item| item.kind == "ip" && item.value.as_deref() == Some("10.20.30.40")));
    assert!(network
        .iter()
        .any(|item| item.kind == "email"
            && item.value.as_deref() == Some("security@corp.example.net")));

    let mut scaled_asset = Vec::new();
    scan_sensitive_text(
        "Payload/MBOMC.app/login_password_icon@2x.png",
        "Archive.txt",
        &mut scaled_asset,
    );
    assert!(scaled_asset
        .iter()
        .filter(|item| item.kind == "email")
        .all(|item| item.filtered));
    assert!(classify_sensitive_name("Payload/MBOMC.app/login_password_icon@2x.png").is_none());
}

#[test]
fn objc_method_classification_uses_selector_signal_not_framework_class_alone() {
    let generic = objc_method_references(
        "AFHTTPRequestSerializer",
        "automaticallyNotifiesObserversForKey:",
    );
    assert!(generic.is_empty());
    assert_eq!(classify_objc_method(&generic), "ios-objc-method");

    let request = objc_method_references(
        "AFHTTPRequestSerializer",
        "requestWithMethod:URLString:parameters:error:",
    );
    assert!(request.iter().any(|value| value == "HTTP request"));
    assert!(request.iter().any(|value| value == "AFNetworking"));
    assert_eq!(classify_objc_method(&request), "ios-network-entry");

    let trust = objc_method_references("AFSecurityPolicy", "evaluateServerTrust:forDomain:");
    assert!(trust.iter().any(|value| value == "certificate trust"));
    assert_eq!(classify_objc_method(&trust), "ios-tls-entry");

    let swift_task_noise =
        objc_method_references("SomeSwiftRuntimeClass", "hasTaskGroupStatusRecord:");
    assert!(swift_task_noise.is_empty());
}

#[test]
fn compact_focus_score_normalizes_objc_selector_colons() {
    let item = CodeInsight {
        platform: "ios".into(),
        kind: "ios-objc-method".into(),
        binary: "Payload/Test.app/Frameworks/AFNetworking.framework/AFNetworking".into(),
        class_name: Some("AFHTTPRequestSerializer".into()),
        name: "+ automaticallyNotifiesObserversForKey:".into(),
        signature: None,
        address: None,
        module_offset: None,
        source_file: None,
        line_number: None,
        runtime_target: None,
        references: Vec::new(),
        snippet: Vec::new(),
        confidence: "high".into(),
    };
    assert_eq!(code_insight_focus_score(&item), -100);
}

#[test]
fn sensitive_scanner_rejects_ios_templates_and_opencv_build_versions() {
    let mut items = Vec::new();
    scan_sensitive_text(
            "mail=_x%d@xCx.xD\nurl=https://%@%@\n/Users/runner/work/opencv-mobile/opencv-mobile-2.4.13.7/modules/core/src/alloc.cpp",
            "Payload/CentralizedAuthentication.app/CentralizedAuthentication",
            &mut items,
        );
    assert!(items
        .iter()
        .filter(|item| ["email", "url", "ip"].contains(&item.kind.as_str()))
        .all(|item| item.filtered));

    let mut valid = Vec::new();
    scan_sensitive_text(
        "mail=security@corp.example.net\nurl=https://auth.corp.internal/fido\nserver=10.23.45.67",
        "Payload/Test.app/Test",
        &mut valid,
    );
    assert!(valid
        .iter()
        .any(|item| item.kind == "email" && !item.filtered));
    assert!(valid
        .iter()
        .any(|item| item.kind == "url" && !item.filtered));
    assert!(valid.iter().any(|item| item.kind == "ip" && !item.filtered));
}

#[test]
fn sensitive_rule_guards_keep_true_crypto_and_filter_algorithm_constants() {
    let mut constant = Vec::new();
    scan_sensitive_text(
        "static const char *oid = md5WithRSAEncryption;",
        "Symbols.txt",
        &mut constant,
    );
    assert!(constant
        .iter()
        .any(|item| item.kind == "weak-crypto" && item.filtered));

    let mut invocation = Vec::new();
    scan_sensitive_text(
        "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
        "Crypto.java",
        &mut invocation,
    );
    assert!(invocation
        .iter()
        .any(|item| item.kind == "weak-crypto" && !item.filtered));
}

#[test]
fn bundled_exclusions_filter_format_and_sm9_log_examples() {
    let mut items = Vec::new();
    scan_sensitive_text(
        "SocksSelectMethod 1.2.3.4 result=%d\nSM9ThreshSign client token: signerdata123456",
        "RuntimeStrings.txt",
        &mut items,
    );
    assert!(items.iter().any(|item| item.kind == "ip" && item.filtered));
    assert!(items
        .iter()
        .any(|item| item.kind == "credential" && item.filtered));
    assert!(items.iter().filter(|item| item.filtered).all(|item| item
        .filter_reason
        .as_deref()
        .is_some_and(|reason| !reason.is_empty())));
}

#[test]
fn frontend_rules_cover_versioned_api_paths_and_filter_cdn_placeholders() {
    let rules = rules::load_rules(None).expect("load frontend-sensitive rules");
    let mut items = Vec::new();
    scan_sensitive_text_with_rules(
        r#"const api = "/v1/users";
const cdn = "https://cdn.jsdelivr.net/npm/vue@3.5.13/dist/vue.js";
const config = { token: "your_secret_token" };"#,
        "assets/app.js",
        &mut items,
        &rules,
        "text-resource",
    );

    assert!(items
        .iter()
        .any(|item| item.kind == "api-endpoint" && !item.filtered));
    assert!(items.iter().any(|item| {
        item.kind == "url"
            && item.filtered
            && item
                .filter_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("excl-frontend-static-cdn-url"))
    }));
    assert!(items.iter().any(|item| {
        item.kind == "credential"
            && item.filtered
            && item
                .filter_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("excl-frontend-placeholder-credential"))
    }));
}

#[test]
fn binary_network_candidates_require_strong_context_but_keep_real_https_domain() {
    let rules = rules::load_rules(None).expect("load sensitive rules");
    let mut noise = Vec::new();
    scan_sensitive_text_with_rules(
        "random 8.8.8.8 x@noise.dev",
        "lib/arm64-v8a/libapp.so",
        &mut noise,
        &rules,
        "binary-strings",
    );
    assert!(noise
        .iter()
        .filter(|item| matches!(item.kind.as_str(), "ip" | "email"))
        .all(|item| item.filtered && item.severity == "low"));

    let mut real = Vec::new();
    scan_sensitive_text_with_rules(
        "baseUrl=https://api.example.com/v1",
        "lib/arm64-v8a/libapp.so",
        &mut real,
        &rules,
        "binary-strings",
    );
    let endpoint = real
        .iter()
        .find(|item| item.kind == "url")
        .expect("real https endpoint");
    assert!(!endpoint.filtered);
    assert_eq!(endpoint.source, "binary-strings");
}

#[test]
fn configured_url_exclusions_support_domains_and_prefixes() {
    let rules = vec![
        "*.example.net".to_string(),
        "https://cdn.corp.test/static/*".to_string(),
    ];
    assert!(url_matches_exclusion("https://api.example.net/v1", &rules));
    assert!(url_matches_exclusion(
        "https://cdn.corp.test/static/logo.png",
        &rules
    ));
    assert!(!url_matches_exclusion("https://api.corp.test/v1", &rules));
}

#[test]
fn recognizes_ios_codeprotect_separately_from_fairplay() {
    let files = vec![
        "Payload/Test.app/Frameworks/JMCodeProtectKit.framework/JMCodeProtectKit".into(),
        "Payload/Test.app/IPACodeProtectTwoSDk_arm64_filter.json".into(),
        "Payload/Test.app/IPACodeProtectTwoSDk_CodeResources".into(),
    ];
    let rule_set = rules::load_rules(None).expect("load external rules");
    let protection = assess_protection(&files, &rule_set);
    assert!(protection
        .packers
        .iter()
        .any(|value| value.contains("JMCodeProtect")));
    assert!(protection
        .indicators
        .iter()
        .any(|value| value.contains("FairPlay cryptid")));
}

#[test]
fn binary_endpoint_samples_are_deduplicated_and_line_ready() {
    let samples = binary_endpoint_samples(
        "https://api.corp.test/v1),\nhttps://api.corp.test/v1),\n/api/v2/users",
        10,
    );
    assert_eq!(
        samples
            .iter()
            .filter(|value| value.as_str() == "https://api.corp.test/v1")
            .count(),
        1
    );
    assert!(samples.iter().any(|value| value == "/api/v2/users"));
}

#[test]
fn includes_flutter_and_ios_macho_binaries_in_deep_scan() {
    assert!(is_deep_binary_candidate("lib/arm64-v8a/libapp.so"));
    assert!(is_deep_binary_candidate("Payload/Runner.app/App"));
    assert!(is_deep_binary_candidate(
        "Payload/Runner.app/Frameworks/App.framework/App"
    ));
    assert!(!is_deep_binary_candidate("Payload/Runner.app/Assets.car"));
}

#[test]
fn ios_compatibility_profiles_are_explicit_and_minimal_is_unmodified() {
    assert_eq!(
        normalize_ios_compatibility_profile(None).as_deref(),
        Ok("minimal")
    );
    assert_eq!(
        normalize_ios_compatibility_profile(Some("Compat")).as_deref(),
        Ok("compat")
    );
    assert!(normalize_ios_compatibility_profile(Some("unsafe-custom")).is_err());

    let source = "console.log('probe');".to_string();
    assert_eq!(
        apply_ios_compatibility_profile(source.clone(), "minimal"),
        source
    );
    let compat = apply_ios_compatibility_profile(source, "compat");
    assert!(compat.contains(r#"__ME_IOS_COMPATIBILITY_PROFILE = "compat""#));
    assert!(compat.contains("isAppCaller"));
    assert!(compat.contains(".app/"));
}

#[test]
fn ios_dump_agent_performs_an_immediate_ready_probe() {
    assert!(IOS_DUMP_AGENT.contains("ready: probeReady"));
    assert!(IOS_DUMP_AGENT.contains("do {\n        result = probeReady();"));
    assert!(!IOS_DUMP_AGENT.contains("ready: function () { return waitReady(0); }"));
    assert!(IOS_DUMP_AGENT.contains("Process.mainModule"));
}

#[test]
fn ios_dump_runner_accepts_the_application_bound_token() {
    let token = "mobilee-test-run-token";
    let bound = IOS_DUMP_RUNNER.replace("__ME_RUN_TOKEN__", token);
    assert!(bound.contains(&format!("EXPECTED_RUN_TOKEN = '{token}'")));
    assert!(bound.contains("TEMPLATE_RUN_TOKEN = '__ME_' + 'RUN_TOKEN__'"));
    assert!(!bound.contains(&format!("EXPECTED_RUN_TOKEN == '{token}'")));
}

#[test]
fn frida_17_spawn_and_attach_arguments_are_unambiguous() {
    let serial = Some("device-1".to_string());
    let script = Path::new("/tmp/test.js");
    let spawn = frida_script_args(&serial, "spawn", "com.example.app", None, script, 60)
        .expect("spawn arguments");
    assert!(spawn
        .windows(2)
        .any(|args| args == ["-f", "com.example.app"]));
    assert!(!spawn.iter().any(|arg| arg == "--no-pause"));

    let attach = frida_script_args(&serial, "attach", "com.example.app", Some(4321), script, 60)
        .expect("attach arguments");
    assert!(attach.windows(2).any(|args| args == ["-p", "4321"]));
    assert!(attach.windows(2).any(|args| args == ["-t", "60"]));
    assert!(frida_script_args(&serial, "attach", "SpringBoard", None, script, 60).is_err());
}

#[test]
fn adapts_legacy_hooker_exports_without_editing_source_file() {
    let source =
        "Module.getExportByName('libc.so', 'open'); Module.findExportByName(null, 'dlopen');";
    let (adapted, changes) = adapt_frida_17_script(source);
    assert!(!adapted.contains("Module.getExportByName"));
    assert!(!adapted.contains("Module.findExportByName"));
    assert!(adapted.contains("Process.getModuleByName('libc.so').getExportByName('open')"));
    assert!(adapted.contains("Module.findGlobalExportByName("));
    assert!(adapted.contains("'dlopen')"));
    assert!(!changes.is_empty());
}

#[test]
fn builtin_scripts_are_available_without_external_directory() {
    let scripts = list_frida_scripts(Some("/directory/that/does/not/exist".into()))
        .expect("list embedded scripts");
    assert!(scripts
        .iter()
        .any(|script| script.path == "builtin://dump_dex.js"));
    assert!(scripts
        .iter()
        .any(|script| script.path == "builtin://dump_so.js"));
    assert!(read_script_path("builtin://dump_so.js")
        .expect("read embedded SO script")
        .contains("[ME_SO_READY]"));
    assert!(read_script_path("builtin://ios_injection_probe.js")
        .expect("read embedded iOS injection probe")
        .contains("ME_IOS_INJECTION_OK"));
    assert!(read_script_path("builtin://observe_jmprotection.js")
        .expect("read embedded JMProtection observer")
        .contains("ME_JM_OBSERVER_READY"));
    assert!(read_script_path("builtin://observe_ios_jsbridge.js")
        .expect("read embedded iOS JSBridge observer")
        .contains("ios-jsbridge"));
}

#[test]
fn static_jsbridge_intelligence_is_categorized_without_runtime_instrumentation() {
    let mut insights = Vec::new();
    analyze_jsbridge_text(
        &mut insights,
        "Payload/Test.app/main.jsbundle",
        "payload/test.app/main.jsbundle",
        "window.webkit.messagehandlers.login.postmessage evaluatejavascript:",
        "window.webkit.messageHandlers.login.postMessage({token: value}); evaluateJavaScript:",
    );
    let categories: HashSet<String> = insights.into_iter().map(|item| item.category).collect();
    assert!(categories.contains("iOS JSBridge 注册/消息入口"));
    assert!(categories.contains("JSBridge Handler 名称候选"));
    assert!(categories.contains("JSBridge 页面调用候选"));
    assert!(categories.contains("JavaScript 动态执行入口"));
}

#[test]
fn framework_risk_signals_require_framework_and_risky_indicator() {
    let mut insights = Vec::new();
    analyze_framework_risk_signals(
        &mut insights,
        "Payload/Test.app/Frameworks/AFNetworking.framework/AFNetworking",
        "payload/test.app/frameworks/afnetworking.framework/afnetworking",
        "afnetworking allowinvalidcertificates nsurlcache authorization",
        "AFNetworking allowInvalidCertificates NSURLCache Authorization",
    );
    assert!(insights
        .iter()
        .any(|item| item.category == "AFNetworking 弱 TLS 配置候选" && item.severity == "high"));
    assert!(insights
        .iter()
        .any(|item| item.category == "AFNetworking 缓存/敏感头候选"));

    let mut no_risk = Vec::new();
    analyze_framework_risk_signals(
        &mut no_risk,
        "Payload/Test.app/Frameworks/AFNetworking.framework/AFNetworking",
        "payload/test.app/frameworks/afnetworking.framework/afnetworking",
        "afnetworking afhttpsessionmanager",
        "AFNetworking AFHTTPSessionManager",
    );
    assert!(no_risk.is_empty());
}

#[tokio::test]
async fn frida_server_starts_as_root_when_device_is_configured() {
    let (Ok(serial), Ok(path)) = (
        std::env::var("ME_ADB_SERIAL"),
        std::env::var("ME_FRIDA_SERVER_PATH"),
    ) else {
        return;
    };
    let result = manage_frida_server(FridaServerRequest {
        serial,
        action: "start".into(),
        path: Some(path),
    })
    .await
    .expect("deploy and start frida-server");
    assert!(result.success, "{}", result.output);
    assert!(result.output.contains("UID=0"), "{}", result.output);
}

#[tokio::test]
async fn frida_server_harden_reports_versions_and_host_connection_when_configured() {
    let Ok(serial) = std::env::var("ME_ADB_SERIAL") else {
        return;
    };
    let result = manage_frida_server(FridaServerRequest {
        serial: serial.clone(),
        action: "harden".into(),
        path: None,
    })
    .await
    .expect("harden frida-server");
    assert!(result.success, "{}", result.output);
    let port = result
        .output
        .lines()
        .find_map(|line| line.strip_prefix("[端口状态] /data/local/tmp/myfs.port = "))
        .and_then(|value| value.trim().parse::<u16>().ok())
        .expect("random hardened port in output");
    assert!((20_000..45_000).contains(&port));
    assert!(
        result
            .output
            .contains(&format!("[环境层] myfs:{port} ✅ 已应用")),
        "{}",
        result.output
    );
    assert!(
        result.output.contains("[版本检查]") && result.output.contains("✅ 一致"),
        "{}",
        result.output
    );
    assert!(
        result
            .output
            .contains(&format!("frida -H 127.0.0.1:{port}")),
        "{}",
        result.output
    );

    let process = run_device_root_script(
        &serial,
        r#"test -n "$(pidof myfs 2>/dev/null)" && test -z "$(pidof frida-server 2>/dev/null)""#,
    )
    .await
    .expect("verify renamed process");
    assert_eq!(process.code, Some(0), "{}", output_text(&process));

    let probe = run_host(
        "frida-ps",
        &["-H".into(), format!("127.0.0.1:{port}"), "-ai".into()],
    )
    .await
    .expect("run hardened frida-ps probe");
    assert_eq!(probe.code, Some(0), "{}", output_text(&probe));
}

#[tokio::test]
async fn matching_frida_ps_lists_apps_when_device_is_configured() {
    let Ok(serial) = std::env::var("ME_ADB_SERIAL") else {
        return;
    };
    let processes = list_frida_processes(Some(serial))
        .await
        .expect("list applications with matching frida-ps");
    assert!(!processes.is_empty());
    if let Ok(package) = std::env::var("ME_FRIDA_TEST_PACKAGE") {
        assert!(
            processes
                .iter()
                .any(|process| process.identifier == package),
            "missing {package}"
        );
    }
}

#[tokio::test]
async fn hooker_dex_workflow_pulls_and_repairs_when_configured() {
    let (Ok(serial), Ok(package), Ok(script_path)) = (
        std::env::var("ME_ADB_SERIAL"),
        std::env::var("ME_FRIDA_TEST_PACKAGE"),
        std::env::var("ME_DEX_DUMP_SCRIPT"),
    ) else {
        return;
    };
    let destination = std::env::temp_dir().join(format!("me-dex-test-{}", now_millis()));
    let result = run_dex_dump(DexDumpRequest {
        serial,
        package,
        script_path,
        destination_directory: Some(destination.to_string_lossy().into_owned()),
        duration_seconds: Some(15),
        mode: None,
        pid: None,
    })
    .await
    .expect("run Hooker DEX workflow");
    assert!(result.success, "{}", result.output);
    assert!(
        destination
            .join("repaired")
            .join("recovered-multidex.zip")
            .is_file(),
        "{}",
        result.output
    );
}

#[tokio::test]
async fn builtin_so_workflow_pulls_ranges_when_configured() {
    let (Ok(serial), Ok(package)) = (
        std::env::var("ME_ADB_SERIAL"),
        std::env::var("ME_FRIDA_TEST_PACKAGE"),
    ) else {
        return;
    };
    let destination = std::env::temp_dir().join(format!("me-so-test-{}", now_millis()));
    let result = run_so_dump(SoDumpRequest {
        serial,
        package,
        script_path: "builtin://dump_so.js".into(),
        destination_directory: Some(destination.to_string_lossy().into_owned()),
        duration_seconds: Some(10),
        mode: None,
        pid: None,
    })
    .await
    .expect("run built-in SO workflow");
    assert!(result.success, "{}", result.output);
    assert!(
        destination.join("raw/so-sensitive-report.json").is_file(),
        "{}",
        result.output
    );
    assert!(
        destination
            .join("repaired/reconstruction-report.json")
            .is_file(),
        "{}",
        result.output
    );
    assert!(
        fs::read_dir(destination.join("repaired"))
            .expect("read repaired directory")
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("repaired-")),
        "{}",
        result.output
    );
}

#[tokio::test]
async fn transparent_proxy_is_root_and_idempotent_when_device_is_configured() {
    let Ok(serial) = std::env::var("ME_ADB_SERIAL") else {
        return;
    };
    let host = std::env::var("ME_PROXY_HOST").unwrap_or_else(|_| "192.168.3.100".into());
    let port = std::env::var("ME_PROXY_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8888);

    run_proxy(ProxyRequest {
        serial: serial.clone(),
        action: "transparent_clear".into(),
        host: Some(host.clone()),
        port: Some(port),
    })
    .await
    .expect("clear old transparent proxy rules");

    for _ in 0..2 {
        let result = run_proxy(ProxyRequest {
            serial: serial.clone(),
            action: "transparent_set".into(),
            host: Some(host.clone()),
            port: Some(port),
        })
        .await
        .expect("set transparent proxy rules");
        assert!(result.success, "{}", result.output);
        assert!(result.output.contains("Root UID=0"), "{}", result.output);
    }

    let rules = run_device_root_script(&serial, "iptables -t nat -S OUTPUT")
        .await
        .expect("list transparent proxy rules");
    let destination = format!("{host}:{port}");
    let matching = rules
        .stdout
        .lines()
        .filter(|line| line.contains(&destination))
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 2, "{}", rules.stdout);
    assert!(matching.iter().any(|line| line.contains("--dport 80")));
    assert!(matching.iter().any(|line| line.contains("--dport 443")));
}
