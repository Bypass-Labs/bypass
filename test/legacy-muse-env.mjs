// Preserve the original blackbox process fixtures' fake Muse transport only
// while running the test suite. Production CLI and plugin inference stay on
// their Meta API and active-host paths.
process.env.BYPASS_TEST_LEGACY_MUSE='1';
