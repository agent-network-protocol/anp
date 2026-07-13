export type BindingGeneration = string & { readonly __bindingGeneration: unique symbol };

export function canonicalizeBindingGeneration(value: unknown): BindingGeneration {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw new TypeError('binding_generation must be a canonical positive decimal string');
  }
  return value as BindingGeneration;
}

export function compareBindingGenerations(
  current: BindingGeneration | string,
  previous: BindingGeneration | string
): number {
  const left = canonicalizeBindingGeneration(current);
  const right = canonicalizeBindingGeneration(previous);
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return left === right ? 0 : left < right ? -1 : 1;
}
