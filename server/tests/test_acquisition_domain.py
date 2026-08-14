from forensix_server.acquisitions.domain import AcquisitionScope, scope_allows_inventory_item


def test_media_scope_recognizes_common_android_image_video_and_audio_formats() -> None:
    for relative_path, extension in (
        ("DCIM/Camera/photo.avif", "AVIF"),
        ("Movies/camera.3gp", "3gp"),
        ("Recordings/interview.opus", "opus"),
        ("Pictures/scan.tiff", "tiff"),
    ):
        assert scope_allows_inventory_item(AcquisitionScope.MEDIA_FILES, relative_path, extension)


def test_document_scope_recognizes_common_exports_and_ebooks() -> None:
    for relative_path, extension in (
        ("Documents/export.json", "json"),
        ("Download/page.html", "html"),
        ("Books/manual.epub", "epub"),
        ("Documents/device.xml", "XML"),
    ):
        assert scope_allows_inventory_item(
            AcquisitionScope.DOCUMENT_FILES, relative_path, extension
        )


def test_file_scopes_still_reject_unrecognized_extensions() -> None:
    assert not scope_allows_inventory_item(
        AcquisitionScope.MEDIA_FILES, "Android/data/blob.bin", "bin"
    )
    assert not scope_allows_inventory_item(
        AcquisitionScope.DOCUMENT_FILES, "Android/data/blob.bin", "bin"
    )
