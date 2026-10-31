from bytasm.review_export import mask_text


def test_plausible_secrets_and_private_paths_are_masked_locally() -> None:
    source = "password=not-a-real-password /Users/example/private/file C:\\Users\\example\\secret"
    masked = mask_text(source)
    assert "not-a-real-password" not in masked
    assert "example" not in masked
    assert "masked" in masked
    assert mask_text("ordinary program settings") == "ordinary program settings"
