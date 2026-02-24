#!/usr/bin/env python3
"""
Run this script after modifying the addon to regenerate zips and addons.xml.
Usage: python3 update_repo.py
"""
import hashlib, os, zipfile

def make_zip(addon_id, version):
    addon_dir = addon_id
    zip_path = f'{addon_dir}/{addon_id}-{version}.zip'
    # Remove old zips
    for f in os.listdir(addon_dir):
        if f.endswith('.zip'):
            os.remove(os.path.join(addon_dir, f))
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(addon_dir):
            dirs[:] = [d for d in dirs if d != '__pycache__']
            for file in files:
                if file.endswith('.zip'):
                    continue
                zf.write(os.path.join(root, file))
    print(f'  Created {zip_path}')

def get_version(addon_id):
    import xml.etree.ElementTree as ET
    tree = ET.parse(f'{addon_id}/addon.xml')
    return tree.getroot().attrib['version']

def build_addons_xml():
    addons_xml = '<?xml version="1.0" encoding="UTF-8"?>\n<addons>\n'
    for addon_id in ['plugin.video.daddylive', 'repository.daddylive']:
        with open(f'{addon_id}/addon.xml', 'r', encoding='utf-8') as f:
            content = f.read()
        start = content.find('<addon ')
        end = content.rfind('</addon>') + len('</addon>')
        addons_xml += content[start:end] + '\n'
    addons_xml += '</addons>\n'
    with open('addons.xml', 'w', encoding='utf-8') as f:
        f.write(addons_xml)
    md5 = hashlib.md5(addons_xml.encode('utf-8')).hexdigest()
    with open('addons.xml.md5', 'w') as f:
        f.write(md5)
    print(f'  addons.xml updated (md5: {md5})')

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    for addon_id in ['plugin.video.daddylive', 'repository.daddylive']:
        v = get_version(addon_id)
        print(f'Packaging {addon_id} v{v}...')
        make_zip(addon_id, v)
    print('Rebuilding addons.xml...')
    build_addons_xml()
    print('Done. Commit and push to GitHub.')
