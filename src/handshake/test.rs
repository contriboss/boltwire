use super::*;

#[test]
fn version_encode_decode() {
    assert_eq!(Version::new(5, 8).encode_range(0), [0, 0, 8, 5]);
    assert_eq!(Version::new(5, 8).encode_range(6), [0, 6, 8, 5]);
    assert_eq!(Version::decode([0, 0, 2, 5]), Version::new(5, 2));
}

#[test]
fn acceptance_window() {
    assert!(supported(Version::new(5, 2)));
    assert!(supported(Version::new(5, 5)));
    assert!(supported(Version::new(5, 8)));
    assert!(!supported(Version::new(5, 1))); // pre-LOGON: old protocol
    assert!(!supported(Version::new(5, 9)));
    assert!(!supported(Version::new(4, 4)));
}

#[test]
fn hello_offers_range_then_floor() {
    let h = client_hello();
    assert_eq!(&h[0..4], &MAGIC);
    assert_eq!(&h[4..8], &[0, 6, 8, 5]); // 5.8 with range 6 -> 5.2..=5.8
    assert_eq!(&h[8..12], &[0, 0, 2, 5]); // plain 5.2 fallback
    assert_eq!(&h[12..20], &[0; 8]);
}
