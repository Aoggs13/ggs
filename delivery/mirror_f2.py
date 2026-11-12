"""Download the public F2 file with a fresh anonymous browser; verify exact bytes."""
import hashlib
from pathlib import Path
import shutil
from playwright.sync_api import sync_playwright

NAME='OXIDE_Q3_ERROR_DETAILS_F2_RESIGN.ipa'
SIZE=949964148
SHA='85aed1404aabe49dd0be8553752dbcb47751b20174eb38859145e0634500c2e6'

with sync_playwright() as p:
    chrome=shutil.which('google-chrome') or shutil.which('google-chrome-stable') or shutil.which('chromium')
    assert chrome,'Expected preinstalled Chrome on the GitHub-hosted runner'
    browser=p.chromium.launch(executable_path=chrome,headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
    context=browser.new_context(accept_downloads=True)
    page=context.new_page()
    page.goto('https://gofile.io/d/ocuLm621',wait_until='domcontentloaded',timeout=60000)
    page.get_by_text(NAME,exact=False).first.wait_for(timeout=60000)
    with page.expect_download(timeout=120000) as pending:
        page.get_by_role('button',name='Download',exact=True).first.click()
    download=pending.value
    assert download.suggested_filename==NAME
    download.save_as(NAME)
    assert download.failure() is None
    browser.close()

path=Path(NAME)
assert path.stat().st_size==SIZE
h=hashlib.sha256()
with path.open('rb') as f:
    while block:=f.read(4<<20):h.update(block)
assert h.hexdigest()==SHA,'Refuse to publish bytes different from the user-requested GoFile F2'
Path('SHA256SUMS.txt').write_text(SHA+'  '+NAME+'\n')
print('Original GoFile bytes and SHA256 verified:',SIZE,SHA,flush=True)
