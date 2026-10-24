/** The ByteHawks mark with the product name. The mark takes the colour of its surroundings. */
export function Brand({ name, by, className = "" }: { name: string; by: string; className?: string }) {
  return (
    <span className={`flex items-center gap-3 ${className}`}>
      <span className="brand-mark size-9 shrink-0" role="img" aria-label={by} />
      <span className="leading-tight">
        <span className="block font-display text-lg font-semibold tracking-tight">{name}</span>
        <span className="block text-[11px] uppercase tracking-widest opacity-70">{by}</span>
      </span>
    </span>
  );
}
