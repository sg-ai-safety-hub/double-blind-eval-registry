// One record: its checks, results, pipeline, and what the registry verified about it. `id` is a validated 64-hex id.
import type { ReactNode } from 'react'
import { useApi, type Check, type RecordJson } from '../lib/api.ts'
import { formatDateTime, formatSize, formatUnix, isHex64, metricValue, plural, reasons } from '../lib/format.ts'
import { externalHref, hrefFor } from '../lib/route.ts'
import { Band, ComponentsTable, Hash, Icon, Info, Link, Section, Table, TIPS, Waiting, idColumn, labelOf } from '../ui.tsx'

// Plain labels for the check ids (registry/model.py CHECK_IDS), with what each one establishes.
const CHECKS: Record<string, { label: string; tip: string }> = {
  signature: { label: 'Enclave signature',
    tip: "The record's signature verifies under the enclave's Ed25519 signing key." },
  key_binding: { label: 'Key bound to hardware', tip: 'The AMD report commits to that signing key.' },
  hardware: { label: 'AMD SEV-SNP report', tip: "The hardware report verifies against AMD's certificate chain." },
  measurement: { label: 'Code matches release',
    tip: 'The enclave ran the Sigstore-signed build of a GitHub release this registry trusts.' },
  digests: { label: 'Configuration digest',
    tip: "The record's subject digest is the hash of the configuration below." },
  consent: { label: 'Whitelisted approver', tip: "An approval comes from an email on this registry's whitelist." },
  publication: { label: 'Logged on Rekor', tip: "Sigstore's public log holds an entry for this signed record." },
}
const CHECKS_PER_ROW = 4

function CheckItem({ check, lastInRow }: { check: Check; lastInRow: boolean }) {
  const { label, tip } = CHECKS[check.id] ?? { label: check.id, tip: check.detail }
  const passed = check.status === 'PASS'
  const pending = check.status === 'PENDING'
  return (
    <li className="check">
      {passed && <span className="ok-i"><Icon name="check" /></span>}
      {pending && <span className="pend-i tip" data-tip={`Pending: ${check.detail}`}><Icon name="clock" /></span>}
      {!passed && !pending && <span className="bad-t">{check.status}</span>}
      <span className="sr">{passed ? 'Passed: ' : pending ? 'Pending: ' : ''}</span>
      {label}
      {pending && <span className="pend-t">pending</span>}
      <Info tip={tip} label={`About ${label}`} right={lastInRow} />
    </li>
  )
}

function StatePill({ record }: { record: RecordJson }) {
  if (record.state === 'verified') {
    return (
      <span className="pill ok tip" data-tip={`All ${plural(record.checks.length, 'check')} passed.`}>
        <Icon name="check" />Verified
      </span>
    )
  }
  return (
    <span className="pill pend tip" data-tip="Some checks could not run. Dev mode only.">
      <Icon name="clock" />Incomplete
    </span>
  )
}

function isNamedMetric(item: unknown): item is { name: string; value: unknown; unit?: unknown } {
  return typeof item === 'object' && item !== null && !Array.isArray(item)
    && typeof (item as Record<string, unknown>).name === 'string' && 'value' in item
}

function Results({ results }: { results: RecordJson['results'] }) {
  const { metrics, counts } = results
  const aside = counts && (
    <span className="sub">{counts.submitted} submitted · {counts.completed} completed · {counts.failed} failed</span>
  )
  return (
    <Section title="Results" aside={aside}>
      {metrics.length === 0 ? <p className="sub">No metrics reported</p> : (
        <Table columns={[{ label: 'Metric' }, { label: 'Value' }, { label: 'Unit' }]}>
          {metrics.map((item, i) => {
            if (!isNamedMetric(item)) return <tr key={i}><td className="mono" colSpan={3}>{JSON.stringify(item)}</td></tr>
            const value = metricValue(item.value)
            return (
              <tr key={i}>
                <td className="mono">{item.name}</td>
                <td className="mono">{value.exact ? <span className="tip" data-tip={value.exact}>{value.text}</span>
                  : value.text}</td>
                <td>{typeof item.unit === 'string' ? item.unit : ''}</td>
              </tr>
            )
          })}
        </Table>
      )}
    </Section>
  )
}

function RailGroup({ title, tip, children }: { title: string; tip?: string; children: ReactNode }) {
  return (
    <div className="rail-g">
      <h2 className="rail-h">{title}{tip && <Info tip={tip} label={`About ${title.toLowerCase()}`} />}</h2>
      {children}
    </div>
  )
}

/** Key/value rows, leaving out any whose value is absent. */
function Rows({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.filter(([, value]) => value !== null && value !== undefined).map(([key, value]) => (
        <div key={key} className="kv-row"><dt>{key}</dt><dd>{value}</dd></div>
      ))}
    </dl>
  )
}

const longHash = (value: string | null, label: string) => value && <Hash value={value} label={label} right />
const reportedTime = (value: string | null) => value && formatDateTime(value, true)

export function RecordPage({ id }: { id: string }) {
  const load = useApi<RecordJson>(`/api/records/${id}`)
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const r = load.data
  const configuration = labelOf([r.subjectName], r.systemDigest)
  const pending = r.checks.filter((c) => c.status === 'PENDING')
  const why = reasons(pending.map((c) => c.detail))
  const download = isHex64(r.recordId) ? `/api/records/${r.recordId}/record.dsse.json` : null
  const rekor = r.publication && externalHref(r.publication.url)
  return (
    <>
      <Band>
        <div className="title-block">
          <div className="title"><h1>{labelOf([r.eval.name], r.eval.digest)}</h1><StatePill record={r} /></div>
          <div className="on">on <Link href={hrefFor('config', r.systemDigest)}>{configuration}</Link></div>
        </div>
        {pending.length > 0 && (
          <div className="notice"><span className="pend-i"><Icon name="clock" /></span>
            <span>{plural(pending.length, 'check')} did not run: {why}.</span></div>
        )}
        <div className="checks-row">
          <span className="checks-h">Checks</span>
          <ul className="checks">
            {r.checks.map((check, i) => (
              <CheckItem key={check.id} check={check} lastInRow={i % CHECKS_PER_ROW === CHECKS_PER_ROW - 1} />
            ))}
          </ul>
        </div>
      </Band>

      <main className="wrap page record">
        <div className="record-main">
          <Results results={r.results} />
          <Section title="Eval dataset">
            <Table columns={[idColumn('Eval'), { label: 'Name' }, { label: 'Scheme' }]}>
              {[<tr key="eval">
                <td className="nowrap">
                  <Hash value={r.eval.digest} href={hrefFor('eval', r.eval.digest)} label={TIPS.copyDigest} quiet />
                </td>
                <td><Link href={hrefFor('eval', r.eval.digest)}>{r.eval.name}</Link></td>
                <td className="mono nowrap">{r.eval.evalSet.scheme}</td>
              </tr>]}
            </Table>
          </Section>
          <Section title="Configuration">
            <ComponentsTable rows={r.components.map((c) => ({ ...c, labels: [c.name] }))} />
          </Section>
        </div>

        <aside className="rail" aria-label="Record details">
          <RailGroup title="Record">
            <Rows rows={[['ID', <Hash value={r.recordId} right />], ['Received', formatDateTime(r.receivedAt)]]} />
            {download && (
              <div className="idc">
                <a className="btn" href={download} download="record.dsse.json">
                  <Icon name="download" />record.dsse.json<span className="sub">{formatSize(r.size)}</span>
                </a>
                <Info tip={TIPS.download} label="About the download" />
              </div>
            )}
          </RailGroup>
          {r.enclave && (
            <RailGroup title="Enclave" tip="Read from the verified AMD report and the Sigstore-signed release.">
              <Rows rows={[['Hardware', r.enclave.type], ['Code', r.enclave.repo],
                ['Release', <span className="mono">{r.enclave.releaseTag}</span>],
                ['Measurement', longHash(r.enclave.measurement, 'Copy full measurement')],
                ['Release digest', longHash(r.enclave.releaseDigest, TIPS.copyDigest)]]} />
            </RailGroup>
          )}
          {r.publication && (
            <RailGroup title="Logged on Rekor" tip="Rekor is Sigstore's public log. The time is Rekor's clock.">
              <Rows rows={[
                ['Log index', rekor
                  ? <a className="mono" href={rekor} target="_blank" rel="noopener noreferrer">{r.publication.logIndex}</a>
                  : <span className="mono">{r.publication.logIndex}</span>],
                ['Logged', formatUnix(r.publication.integratedTime)]]} />
            </RailGroup>
          )}
          <RailGroup title="Approved by" tip={TIPS.approvedBy}>
            <div><div>{r.benchmarkOwner.display}</div><div className="sub">{r.benchmarkOwner.email}</div></div>
          </RailGroup>
          <RailGroup title="Reported in the record" tip="Signed by the enclave, but not checked by this registry.">
            <Rows rows={[['Platform', r.reported.platform],
              ['CVM version', r.reported.cvmVersion && <span className="mono">{r.reported.cvmVersion}</span>],
              ['Run ID', longHash(r.reported.runId, 'Copy full run ID')],
              ['Config digest', longHash(r.reported.configDigest, TIPS.copyDigest)],
              ['Started', reportedTime(r.reported.startedAt)], ['Finished', reportedTime(r.reported.finishedAt)]]} />
          </RailGroup>
        </aside>
      </main>
    </>
  )
}
