from onaa_registry.brand import ICON_FILES


def test_icon_files_are_served(client):
    for path, (_, media_type) in ICON_FILES.items():
        r = client.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-type"].startswith(media_type), path
        assert len(r.content) > 100, path


def test_home_links_the_icon(client):
    page = client.get("/", headers={"accept": "text/html"}).text
    assert 'rel="icon" href="/favicon.ico"' in page
    assert 'rel="apple-touch-icon"' in page
    assert 'class="logo-mark" src="/icon.svg"' in page
