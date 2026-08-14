import { BarChart3, Cell, ResponsiveContainer, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts'

interface BalanceChartProps {
  data: Record<string, { balance: number | null }>
}

const COLORS = ['#3b82f6', '#8b5cf6', '#22c55e', '#f59e0b', '#ef4444']

export function BalanceChart({ data }: BalanceChartProps) {
  const chartData = Object.entries(data).map(([chain, values], idx) => ({
    name: chain.charAt(0).toUpperCase() + chain.slice(1),
    balance: values.balance ?? 0,
    fill: COLORS[idx % COLORS.length]
  }))

  return (
    <div className="h-48 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip 
            formatter={(value: number) => [`${value.toFixed(6)}`, 'Balance']}
          />
          <Legend />
          <Bar dataKey="balance" fill="#8884d8">
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.fill as string} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}