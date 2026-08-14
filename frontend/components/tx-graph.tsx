'use client'

import { useState } from 'react'
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  useNodesState,
  useEdgesState
} from 'reactflow'
import 'reactflow/dist/style.css'
import { AnalysisResponse, ChainData } from '@/app/explorer/page'

interface TxGraphProps {
  data: AnalysisResponse
}

interface AddressNode extends Node {
  data: {
    label: string
    chain: string
    balance: number | null
  }
}

export function TxGraph({ data }: TxGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<AddressNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useState(() => {
    const addressNode: AddressNode = {
      id: 'root',
      type: 'input',
      position: { x: 0, y: 0 },
      data: { 
        label: data.address.slice(0, 16) + '...',
        chain: 'multiple',
        balance: 0
      }
    }

    const chainNodes: AddressNode[] = []
    const chainEdges: Edge[] = []

    Object.entries(data.chains).forEach(([chain, chainData], idx) => {
      const node: AddressNode = {
        id: chain,
        position: { x: 200, y: (idx - 2) * 150 },
        data: {
          label: chain.toUpperCase(),
          chain,
          balance: chainData.balance
        }
      }
      chainNodes.push(node)
      chainEdges.push({
        id: `e-root-${chain}`,
        source: 'root',
        target: chain,
        animated: true
      })
    })

    setNodes([addressNode, ...chainNodes])
    setEdges(chainEdges)
  }, [data])

  const nodeTypes = {
    input: ({ data }: { data: { label: string; chain: string; balance: number | null } }) => (
      <div className="bg-primary text-white px-4 py-2 rounded-full font-semibold text-sm">
        {data.label}
      </div>
    ),
    default: ({ data }: { data: { label: string; chain: string; balance: number | null } }) => (
      <div className="bg-slate-100 border border-slate-300 px-3 py-2 rounded-lg">
        <div className="font-medium text-sm">{data.label}</div>
        {data.balance !== null && (
          <div className="text-xs text-slate-500">{data.balance.toFixed(4)}</div>
        )}
      </div>
    )
  }

  const edgeTypes = {
    animated: ({ style }: { style: React.CSSProperties }) => (
      <path
        style={style}
        className="stroke-primary"
        strokeWidth={2}
      />
    )
  }

  if (!data || Object.keys(data.chains).length === 0) {
    return (
      <div className="h-64 flex items-center justify-center bg-slate-50 rounded-lg">
        <p className="text-slate-500">Enter an address to see transaction graph</p>
      </div>
    )
  }

  return (
    <div className="h-64 w-full rounded-lg border">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        AttributionPosition="bottom-left"
      >
        <Controls />
        <Background />
      </ReactFlow>
    </div>
  )
}

import { Card } from '@/components/ui/card'