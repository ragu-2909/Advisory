import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import ExcelJS from 'exceljs';
import { z } from 'zod';
import type { CrowdStrikeApplicationMatch } from '../connectors/crowdstrike.js';

const directory = join(process.cwd(), 'data');
export async function saveSetting(name: string, value: unknown) {
  await mkdir(directory, { recursive: true });
  const path = join(directory, name + '.json');
  const temp = path + randomUUID();
  await writeFile(temp, JSON.stringify(value), { mode: 0o600 });
  await rename(temp, path);
}
export async function readSetting<T>(name: string, fallback: T): Promise<T> {
  try { return JSON.parse(await readFile(join(directory, name + '.json'), 'utf8')); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return fallback; throw error; }
}
export const sourceName = z.string().regex(/^[a-z0-9_-]{1,48}$/i);
type Inventory = { name: string; updated: string; rows: CrowdStrikeApplicationMatch[] };
export async function inventories() {
  const { readdir } = await import('node:fs/promises');
  const names = await readdir(directory).catch(error => { if (error.code === 'ENOENT') return [] as string[]; throw error; });
  return Promise.all(names.filter(name => /^inventory-[a-z0-9_-]+\.json$/i.test(name)).map(name => readSetting<Inventory>(name.slice(0,-5), { name, updated: '', rows: [] })));
}
export async function importInventory(name: string, bytes: Buffer) {
  sourceName.parse(name);
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(Uint8Array.from(bytes).buffer);
  const sheet = workbook.worksheets[0];
  if (!sheet || sheet.rowCount > 20001) throw new Error('Use one worksheet with at most 20,000 inventory rows.');
  const columns = new Map<string, number>();
  sheet.getRow(1).eachCell((cell, col) => columns.set(cell.text.trim().toLowerCase(), col));
  for (const key of ['hostname','product','version','vendor']) if (!columns.has(key)) throw new Error('Required columns: hostname, product, version, vendor.');
  const rows: CrowdStrikeApplicationMatch[] = [];
  sheet.eachRow((row, number) => {
    if (number === 1) return;
    const field = (key: string) => columns.has(key) ? row.getCell(columns.get(key)!).text.trim() : '';
    const hostname = field('hostname'), product = field('product');
    if (!hostname || !product || !field('version')) throw new Error('Missing hostname, product or version on row ' + number);
    rows.push({ applicationId: JSON.stringify([hostname, product, field('version')]), hostId: hostname,
      name: product, version: field('version'), vendor: field('vendor'), architecture: field('architecture'),
      installationPaths: [], application: { inventorySource: name }, host: { hostname, local_ip: field('ip') },
      exposure: field('internetfacing').toLowerCase() === 'true' ? true : field('internetfacing').toLowerCase() === 'false' ? false : null });
  });
  if (!rows.length) throw new Error('Workbook contains no inventory rows.');
  await saveSetting('inventory-' + name.toLowerCase(), { name, updated: new Date().toISOString(), rows });
  return { name, count: rows.length };
}
