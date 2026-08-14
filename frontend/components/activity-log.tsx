interface ActivityLogProps {
  activities: string[]
  className?: string
}

export function ActivityLog({ activities, className }: ActivityLogProps) {
  if (activities.length === 0) {
    return (
      <div className={className}>
        <p className="text-slate-500 text-sm py-4">No activity yet</p>
      </div>
    )
  }

  return (
    <div className={className}>
      <div className="space-y-1 max-h-64 overflow-y-auto">
        {activities.map((activity, idx) => (
          <div 
            key={idx} 
            className="text-xs font-mono bg-slate-50 p-2 rounded-md"
          >
            {activity}
          </div>
        ))}
      </div>
    </div>
  )
}