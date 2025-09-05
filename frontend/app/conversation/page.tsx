"use client"

import { useState, useEffect, useRef } from "react"
import { Shield, Loader2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useConversation } from "../contexts/ConversationContext"

interface Message {
  id: string
  role: "investigator" | "interrogator" | "referee" | "system"
  content: string
  timestamp: Date
  severity?: "critical" | "high" | "medium" | "low"
}


export default function ConversationPage() {
  const [isComplete, setIsComplete] = useState(false)
  const [ws, setWs] = useState<WebSocket | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const { messages, addMessage, setMessages } = useConversation()

  useEffect(() => {
    // Connect to WebSocket
    const websocket = new WebSocket('ws://localhost:8000/ws')
    
    websocket.onopen = () => {
      console.log('WebSocket connected')
      setWs(websocket)
      
      // Get code from sessionStorage and send to backend
      const codeToAnalyze = sessionStorage.getItem('codeToAnalyze')
      if (codeToAnalyze) {
        console.log("TESTESTSETSST")
        // Clear the stored code
        sessionStorage.removeItem('codeToAnalyze')
        
        // Send code to backend for analysis
        fetch('http://localhost:8000/api/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            code: codeToAnalyze
          })
        })
        .then(response => response.json())
        .then(result => {
          console.log('Analysis started:', result)
        })
        .catch(error => {
          console.error('Failed to start analysis:', error)
        })
      }
      
      // Send periodic heartbeat to keep connection alive
      const heartbeat = setInterval(() => {
        if (websocket.readyState === WebSocket.OPEN) {
          websocket.send(JSON.stringify({ type: 'heartbeat', timestamp: Date.now() }))
          console.log('💓 Sent heartbeat')
        } else {
          clearInterval(heartbeat)
        }
      }, 10000) // Send heartbeat every 10 seconds
    }
    
    websocket.onmessage = (event) => {
      const data = JSON.parse(event.data)
      console.log('Received WebSocket message:', data)
      
      // Handle different message types
      if (data.type === 'connection_established') {
        console.log('✅ WebSocket connection confirmed:', data.message)
        return
      }
      
      if (data.type === 'analysis_started' || 
          data.type === 'chunks_loaded' || 
          data.type === 'chunk_complete') {
        // System messages - don't show in conversation
        console.log('System message:', data.message)
        return
      }
      
      // Convert WebSocket message to our Message format and add to context
      const messageRole = data.type === 'interrogator_message' ? 'interrogator' : 
                         data.type === 'investigator_message' ? 'investigator' :
                         data.type === 'referee_message' ? 'referee' : 'system'
      
      console.log('Adding message to conversation:', { role: messageRole, content: data.message })
      addMessage({
        role: messageRole,
        content: data.message
      })
      
      // Auto-scroll to bottom when new message arrives
      setTimeout(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
      }, 100)
      
      // Check if analysis is complete or errored
      if (data.type === 'analysis_complete') {
        console.log('Analysis complete, redirecting to report...')
        
        // Store analysis result and conversation log as backup
        if (data.report) {
          sessionStorage.setItem('analysisResult', JSON.stringify(data.report))
        }
        // Store conversation log to sessionStorage as backup for report page
        sessionStorage.setItem('conversationLog', JSON.stringify(messages))
        
        setIsComplete(true)
        setTimeout(() => {
          window.location.href = "/report"
        }, 2000)
      } else if (data.type === 'analysis_error') {
        console.error('Analysis failed:', data.message)
        
        // Add error message to conversation
        addMessage({
          role: 'system',
          content: `Analysis failed: ${data.message}`
        })
        
        // Still redirect to report page after delay
        setIsComplete(true)
        setTimeout(() => {
          window.location.href = "/report"
        }, 3000)
      }
    }
    
    websocket.onclose = () => {
      console.log('WebSocket disconnected')
    }
    
    websocket.onerror = (error) => {
      console.error('WebSocket error:', error)
    }
    
    return () => {
      websocket.close()
    }
  }, [])

  const getRoleIcon = (role: string) => {
    switch (role) {
      case "investigator":
        return <Shield className="h-4 w-4" />
      case "interrogator":
        return <Shield className="h-4 w-4" />
      default:
        return <Shield className="h-4 w-4" />
    }
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case "investigator":
        return "bg-blue-500/10 border-blue-500/20 text-blue-400"
      case "interrogator":
        return "bg-red-500/10 border-red-500/20 text-red-400"
      case "referee":
        return "bg-purple-500/10 border-purple-500/20 text-purple-400"
      case "system":
        return "bg-green-500/10 border-green-500/20 text-green-400"
      default:
        return "bg-muted"
    }
  }

  const getSeverityBadge = (severity?: string) => {
    if (!severity) return null
    
    const variants = {
      critical: "critical" as const,
      high: "destructive" as const,
      medium: "warning" as const,
      low: "secondary" as const
    }
    
    return (
      <Badge variant={variants[severity as keyof typeof variants] || "secondary"} className="ml-2">
        {severity.toUpperCase()}
      </Badge>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-blue-400 bg-clip-text text-transparent">
                CodeSentinel
              </h1>
              <p className="text-sm text-muted-foreground">AI-Powered Security Analysis</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <div className="max-w-4xl mx-auto space-y-8">
          {/* Loading Indicator */}
          <div className="text-center space-y-4">
            <div className="flex justify-center">
              {isComplete ? (
                <div className="h-12 w-12 rounded-full bg-green-500 flex items-center justify-center">
                  <Shield className="h-6 w-6 text-white" />
                </div>
              ) : (
                <Loader2 className="h-12 w-12 animate-spin text-primary" />
              )}
            </div>
            <div className="text-lg text-muted-foreground">
              {isComplete ? "Analysis Complete!" : "Analyzing Code..."}
            </div>
          </div>

          {/* AI Agent Discussion */}
          <Card className="border-border">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>AI Agent Discussion</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="max-h-96 overflow-y-auto space-y-4 pr-2">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={`p-4 rounded-lg border ${getRoleColor(message.role)}`}
                  >
                    <div className="flex items-center space-x-2 mb-2">
                      {getRoleIcon(message.role)}
                      <span className="font-medium capitalize">{message.role}</span>
                      {getSeverityBadge(message.severity)}
                      <span className="text-xs text-muted-foreground ml-auto">
                        {message.timestamp.toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-sm leading-relaxed whitespace-pre-wrap">
                      {message.content.split('```').map((part, index) => {
                        if (index % 2 === 1) {
                          // This is a code block
                          const [language, ...codeLines] = part.split('\n')
                          const code = codeLines.join('\n')
                          return (
                            <pre key={index} className="bg-muted p-3 rounded-md overflow-x-auto my-2">
                              <code className={`language-${language}`}>{code}</code>
                            </pre>
                          )
                        }
                        return part
                      })}
                    </div>
                  </div>
                ))}
                
                {!isComplete && (
                  <div className="flex items-center space-x-2 text-muted-foreground">
                    <div className="animate-pulse">●</div>
                    <span className="text-sm">AI agents are analyzing...</span>
                  </div>
                )}
                
                {/* Auto-scroll target */}
                <div ref={messagesEndRef} />
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}
