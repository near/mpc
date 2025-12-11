use tempfile::tempdir;

include!("../build_support/lib.rs");

#[test]
fn test_generate_measurements_with_exact_values() {
    // Create temporary input + output directories
    let assets = tempdir().expect("tmp assets");
    let out = tempdir().expect("tmp out dir");

    // Fake input JSON matching your real measurement values
    let fake_json = r#"{
        "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
        "rtmr0": "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
        "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
        "rtmr2": "24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe",
        "event_log": [
            {
                "event": "key-provider",
                "digest": "74ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f"
            }
        ]
    }"#;

    // Write fake JSON input file
    let json_path = assets.path().join("tcb_info_test.json");
    fs::write(&json_path, fake_json).expect("write fake json");

    // Output Rust file path
    let out_file = out.path().join("measurements_generated.rs");

    // Run the generator
    generate_measurements(assets.path(), &out_file)
        .expect("generation failed");

    // Read the generated Rust file
    let generated = fs::read_to_string(&out_file).expect("read output");

    // Expected byte arrays (computed from your hex)
    let expected_mrtd = "[240, 109, 253, 166, 220, 225, 207, 144, 77, 78, 43, 171, 29, 195, 112, 99, 76, 249, 92, 239, 162, 206, 178, 222, 46, 238, 18, 124, 147, 130, 105, 128, 144, 215, 164, 161, 62, 20, 197, 54, 236, 108, 156, 60, 143, 168, 112, 119]";
    let expected_rtmr0 = "[230, 115, 190, 47, 112, 190, 239, 183, 11, 72, 166, 16, 158, 237, 71, 21, 215, 39, 13, 70, 131, 179, 191, 53, 111, 162, 95, 175, 191, 26, 167, 110, 57, 233, 18, 126, 110, 104, 140, 205, 169, 139, 218, 177, 212, 212, 127, 70]";
    let expected_rtmr1 = "[167, 181, 35, 39, 141, 79, 145, 78, 232, 223, 14, 200, 12, 209, 195, 212, 152, 203, 241, 21, 43, 12, 94, 175, 101, 186, 217, 66, 80, 114, 135, 74, 63, 207, 137, 30, 139, 1, 113, 61, 61, 153, 55, 227, 224, 210, 108, 21]";
    let expected_rtmr2 = "[36, 132, 127, 92, 90, 35, 96, 208, 48, 188, 79, 123, 133, 119, 206, 50, 232, 124, 77, 5, 20, 82, 201, 55, 233, 18, 32, 202, 182, 149, 66, 218, 239, 131, 67, 57, 71, 196, 146, 185, 194, 1, 24, 47, 201, 118, 155, 190]";
    let expected_digest = "[116, 202, 147, 155, 140, 60, 116, 170, 179, 195, 9, 102, 167, 136, 247, 116, 57, 81, 213, 74, 147, 106, 113, 29, 208, 20, 34, 240, 3, 255, 157, 246, 102, 111, 60, 197, 73, 117, 210, 228, 243, 92, 130, 152, 101, 88, 63, 15]";

    // Assert exact matches appear in the generated code
    assert!(generated.contains(expected_mrtd), "mrtd mismatch");
    assert!(generated.contains(expected_rtmr0), "rtmr0 mismatch");
    assert!(generated.contains(expected_rtmr1), "rtmr1 mismatch");
    assert!(generated.contains(expected_rtmr2), "rtmr2 mismatch");
    assert!(generated.contains(expected_digest), "digest mismatch");
}

#[test]
fn test_generate_measurements_with_two_files() {
    use tempfile::tempdir;
    use std::fs;
   
    // Create temporary input + output directories
    let assets = tempdir().expect("tmp assets");
    let out = tempdir().expect("tmp out dir");

    // -------- JSON FILE #1 (same as in first test) --------
    let json1 = r#"{
        "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
        "rtmr0": "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
        "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
        "rtmr2": "24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe",
        "event_log": [
            {
                "event": "key-provider",
                "digest": "74ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f"
            }
        ]
    }"#;

    // -------- JSON FILE #2 (your new values) --------
    let json2 = r#"{
        "mrtd": "a06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
        "rtmr0": "a673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
        "rtmr1": "d7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
        "rtmr2": "abf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
        "event_log": [
            {
                "event": "key-provider",
                "digest": "64ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f"
            }
        ]
    }"#;

    // Write both input JSON files
    fs::write(assets.path().join("tcb_info_test1.json"), json1).unwrap();
    fs::write(assets.path().join("tcb_info_test2.json"), json2).unwrap();

    // Output Rust file path
    let out_file = out.path().join("measurements_generated.rs");

    // Run generator
    generate_measurements(assets.path(), &out_file).expect("generation failed");

    // Read generated file
    let generated = fs::read_to_string(&out_file).expect("read output");

    // -------- Expected byte arrays for JSON #1 --------
    let mrtd1 = "[240, 109, 253, 166, 220, 225, 207, 144, 77, 78, 43, 171, 29, 195, 112, 99, 76, 249, 92, 239, 162, 206, 178, 222, 46, 238, 18, 124, 147, 130, 105, 128, 144, 215, 164, 161, 62, 20, 197, 54, 236, 108, 156, 60, 143, 168, 112, 119]";
    let rtmr01 = "[230, 115, 190, 47, 112, 190, 239, 183, 11, 72, 166, 16, 158, 237, 71, 21, 215, 39, 13, 70, 131, 179, 191, 53, 111, 162, 95, 175, 191, 26, 167, 110, 57, 233, 18, 126, 110, 104, 140, 205, 169, 139, 218, 177, 212, 212, 127, 70]";
    let rtmr11 = "[167, 181, 35, 39, 141, 79, 145, 78, 232, 223, 14, 200, 12, 209, 195, 212, 152, 203, 241, 21, 43, 12, 94, 175, 101, 186, 217, 66, 80, 114, 135, 74, 63, 207, 137, 30, 139, 1, 113, 61, 61, 153, 55, 227, 224, 210, 108, 21]";
    let rtmr21 = "[36, 132, 127, 92, 90, 35, 96, 208, 48, 188, 79, 123, 133, 119, 206, 50, 232, 124, 77, 5, 20, 82, 201, 55, 233, 18, 32, 202, 182, 149, 66, 218, 239, 131, 67, 57, 71, 196, 146, 185, 194, 1, 24, 47, 201, 118, 155, 190]";
    let digest1 = "[116, 202, 147, 155, 140, 60, 116, 170, 179, 195, 9, 102, 167, 136, 247, 116, 57, 81, 213, 74, 147, 106, 113, 29, 208, 20, 34, 240, 3, 255, 157, 246, 102, 111, 60, 197, 73, 117, 210, 228, 243, 92, 130, 152, 101, 88, 63, 15]";

    // -------- Expected byte arrays for JSON #2 --------
    let mrtd2 = "[160, 109, 253, 166, 220, 225, 207, 144, 77, 78, 43, 171, 29, 195, 112, 99, 76, 249, 92, 239, 162, 206, 178, 222, 46, 238, 18, 124, 147, 130, 105, 128, 144, 215, 164, 161, 62, 20, 197, 54, 236, 108, 156, 60, 143, 168, 112, 119]";
    let rtmr02 = "[166, 115, 190, 47, 112, 190, 239, 183, 11, 72, 166, 16, 158, 237, 71, 21, 215, 39, 13, 70, 131, 179, 191, 53, 111, 162, 95, 175, 191, 26, 167, 110, 57, 233, 18, 126, 110, 104, 140, 205, 169, 139, 218, 177, 212, 212, 127, 70]";
    let rtmr12 = "[215, 181, 35, 39, 141, 79, 145, 78, 232, 223, 14, 200, 12, 209, 195, 212, 152, 203, 241, 21, 43, 12, 94, 175, 101, 186, 217, 66, 80, 114, 135, 74, 63, 207, 137, 30, 139, 1, 113, 61, 61, 153, 55, 227, 224, 210, 108, 21]";
    let rtmr22 = "[171, 244, 146, 76, 7, 245, 6, 111, 61, 198, 133, 152, 68, 24, 67, 68, 48, 106, 163, 38, 56, 23, 21, 61, 202, 238, 133, 175, 151, 210, 62, 12, 11, 150, 239, 224, 115, 29, 136, 101, 168, 116, 126, 81, 185, 227, 81, 172]";
    let digest2 = "[100, 202, 147, 155, 140, 60, 116, 170, 179, 195, 9, 102, 167, 136, 247, 116, 57, 81, 213, 74, 147, 106, 113, 29, 208, 20, 34, 240, 3, 255, 157, 246, 102, 111, 60, 197, 73, 117, 210, 228, 243, 92, 130, 152, 101, 88, 63, 15]";

    // -------- Assertions for entry #1 --------
    assert!(generated.contains(mrtd1), "JSON1 mrtd mismatch");
    assert!(generated.contains(rtmr01), "JSON1 rtmr0 mismatch");
    assert!(generated.contains(rtmr11), "JSON1 rtmr1 mismatch");
    assert!(generated.contains(rtmr21), "JSON1 rtmr2 mismatch");
    assert!(generated.contains(digest1), "JSON1 digest mismatch");

    // -------- Assertions for entry #2 --------
    assert!(generated.contains(mrtd2), "JSON2 mrtd mismatch");
    assert!(generated.contains(rtmr02), "JSON2 rtmr0 mismatch");
    assert!(generated.contains(rtmr12), "JSON2 rtmr1 mismatch");
    assert!(generated.contains(rtmr22), "JSON2 rtmr2 mismatch");
    assert!(generated.contains(digest2), "JSON2 digest mismatch");
}