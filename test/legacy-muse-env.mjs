// Preserve the original blackbox process fixtures' fake Muse transport only
// while running the test suite. Production CLI and plugin inference stay on
// their Meta API and active-host paths.
process.env.BYPASS_TEST_LEGACY_MUSE='1';
// Fixture replays use their ephemeral origin; only tests that explicitly opt in
// to CI should require BYPASS_BLACKBOX_TEST_ORIGIN.
delete process.env.CI;
