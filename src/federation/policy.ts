import type { FederationMetadata, MetadataPolicy } from './entity.js'

/**
 * Subset of OpenID Federation 1.0 metadata policy (section 6.1):
 * operators value, add, default, one_of, subset_of, superset_of, essential.
 */
type Ops = Record<string, unknown>

const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : [v])
const eq = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)
const union = (a: unknown[], b: unknown[]) => [...a, ...b.filter((x) => !a.some((y) => eq(x, y)))]
const intersect = (a: unknown[], b: unknown[]) => a.filter((x) => b.some((y) => eq(x, y)))

const mergeOps = (superior: Ops, subordinate: Ops, where: string): Ops => {
  const out: Ops = { ...superior }
  for (const [op, v] of Object.entries(subordinate)) {
    if (!(op in out)) {
      out[op] = v
      continue
    }
    switch (op) {
      case 'value':
      case 'default':
        if (!eq(out[op], v)) throw new Error(`policy conflict on ${where}.${op}`)
        break
      case 'add':
      case 'superset_of':
        out[op] = union(asArray(out[op]), asArray(v))
        break
      case 'one_of':
      case 'subset_of':
        out[op] = intersect(asArray(out[op]), asArray(v))
        break
      case 'essential':
        out[op] = Boolean(out[op]) || Boolean(v)
        break
      default:
        throw new Error(`unsupported metadata policy operator: ${op}`)
    }
  }
  return out
}

/** Merges policies ordered from Trust Anchor (first) down to the leaf's superior (last). */
export const mergePolicies = (policies: MetadataPolicy[]): MetadataPolicy => {
  const merged: MetadataPolicy = {}
  for (const policy of policies) {
    for (const [type, params] of Object.entries(policy)) {
      merged[type] ??= {}
      for (const [param, ops] of Object.entries(params)) {
        merged[type][param] = merged[type][param]
          ? mergeOps(merged[type][param], ops, `${type}.${param}`)
          : { ...ops }
      }
    }
  }
  return merged
}

export const applyPolicy = (
  metadata: FederationMetadata,
  policy: MetadataPolicy
): FederationMetadata => {
  const out: FederationMetadata = structuredClone(metadata)
  for (const [type, params] of Object.entries(policy)) {
    if (!out[type]) continue
    const md = out[type]
    for (const [param, ops] of Object.entries(params)) {
      const where = `${type}.${param}`
      if ('value' in ops) {
        if (ops.value === null) delete md[param]
        else md[param] = ops.value
      }
      if ('add' in ops) {
        md[param] = union(md[param] === undefined ? [] : asArray(md[param]), asArray(ops.add))
      }
      if ('default' in ops && md[param] === undefined) md[param] = ops.default
      if ('one_of' in ops && md[param] !== undefined) {
        if (!asArray(ops.one_of).some((x) => eq(x, md[param]))) {
          throw new Error(`${where} violates one_of policy`)
        }
      }
      if ('subset_of' in ops && md[param] !== undefined) {
        const filtered = intersect(asArray(md[param]), asArray(ops.subset_of))
        if (filtered.length === 0) delete md[param]
        else md[param] = filtered
      }
      if ('superset_of' in ops && md[param] !== undefined) {
        const values = asArray(md[param])
        if (!asArray(ops.superset_of).every((x) => values.some((y) => eq(x, y)))) {
          throw new Error(`${where} violates superset_of policy`)
        }
      }
      if (ops.essential === true && md[param] === undefined) {
        throw new Error(`${where} is essential but missing`)
      }
    }
  }
  return out
}
