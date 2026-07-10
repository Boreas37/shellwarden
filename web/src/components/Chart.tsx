// Tiny dependency-free SVG area chart for resource time series.
interface ChartProps {
  values: number[];
  label: string;
  unit?: string;
  color?: string;
  max?: number; // fixed scale (e.g. 100 for %)
}

export default function Chart({ values, label, unit = "", color = "#38c6d9", max }: ChartProps) {
  const W = 100;
  const H = 34;
  const n = values.length;
  const peak = Math.max(max ?? 0, ...values, 0.0001);
  const scale = max ?? peak;
  const cur = n ? values[n - 1] : 0;

  const pts =
    n > 1
      ? values.map((v, i) => `${(i / (n - 1)) * W},${H - Math.min(v / scale, 1) * H}`).join(" ")
      : "";

  return (
    <div className="chart">
      <div className="chart-head">
        <span className="chart-label">{label}</span>
        <span className="chart-cur" style={{ color }}>
          {cur.toFixed(1)}
          {unit}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="chart-svg">
        {n > 1 && (
          <>
            <polygon points={`0,${H} ${pts} ${W},${H}`} fill={color} fillOpacity="0.14" />
            <polyline points={pts} fill="none" stroke={color} strokeWidth="1" vectorEffect="non-scaling-stroke" />
          </>
        )}
      </svg>
      <div className="chart-foot">
        peak {peak.toFixed(1)}
        {unit} · {n} pts
      </div>
    </div>
  );
}
