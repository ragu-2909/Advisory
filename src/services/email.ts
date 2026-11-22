export interface MailHost { host: string; product: string; version?: string; ip?: string; exposure: boolean | null; source?: string }
const escape = (value: unknown) => String(value ?? 'Unknown').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]!);
export function advisoryEmail(subject: string, summary: string, hosts: MailHost[]) {
  const rows = hosts.map(h => [h.host,h.ip,h.product,h.version,h.exposure == null ? 'Unknown' : h.exposure ? 'Yes' : 'No',h.source ?? 'CrowdStrike']);
  const table = '<table cellpadding="6" border="1"><thead><tr>' + ['Host','IP','Application','Installed version','Internet facing','Source'].map(v=>'<th>'+v+'</th>').join('') + '</tr></thead><tbody>' + rows.map(row=>'<tr>'+row.map(v=>'<td>'+escape(v)+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
  return { subject, body: { contentType:'html', executiveSummary:summary, affectedHosts:hosts, html:'<h2>'+escape(subject)+'</h2><p>'+escape(summary)+'</p>'+(rows.length ? table : '<p>No confirmed affected installations in the available evidence.</p>') } };
}
