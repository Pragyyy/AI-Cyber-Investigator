import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const COLORS = {
  LOW: "#2e7d32",
  MEDIUM: "#b8860b",
  HIGH: "#d84315",
  CRITICAL: "#c62828",
};

export default function SeverityChart({ severityCounts }) {
  const data = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((level) => ({
    level,
    count: severityCounts[level] || 0,
  }));

  const allZero = data.every((d) => d.count === 0);
  if (allZero) {
    return <p className="text-faint">No incidents to chart yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 4, right: 16, left: -16, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2a2e40" vertical={false} />
        <XAxis dataKey="level" stroke="#9096ab" fontSize={12} />
        <YAxis stroke="#9096ab" fontSize={12} allowDecimals={false} />
        <Tooltip
          contentStyle={{
            background: "#1c2030",
            border: "1px solid #2a2e40",
            borderRadius: 6,
            fontSize: 12,
          }}
          labelStyle={{ color: "#e6e8f0" }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((d) => (
            <Cell key={d.level} fill={COLORS[d.level]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
