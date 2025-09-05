"use client"

import React, { createContext, useContext, useState, ReactNode } from 'react'

interface ConversationMessage {
  id: string
  role: "investigator" | "interrogator" | "referee" | "system"
  content: string
  timestamp: Date
  severity?: "critical" | "high" | "medium" | "low"
}

interface ConversationContextType {
  messages: ConversationMessage[]
  addMessage: (message: Omit<ConversationMessage, 'id' | 'timestamp'>) => void
  clearMessages: () => void
  setMessages: (messages: ConversationMessage[]) => void
}

const ConversationContext = createContext<ConversationContextType | undefined>(undefined)

export function ConversationProvider({ children }: { children: ReactNode }) {
  const [messages, setMessagesState] = useState<ConversationMessage[]>([])

  const addMessage = (message: Omit<ConversationMessage, 'id' | 'timestamp'>) => {
    const newMessage: ConversationMessage = {
      ...message,
      id: `msg_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date()
    }
    setMessagesState(prev => [...prev, newMessage])
  }

  const clearMessages = () => {
    setMessagesState([])
  }

  const setMessages = (newMessages: ConversationMessage[]) => {
    setMessagesState(newMessages)
  }

  return (
    <ConversationContext.Provider value={{
      messages,
      addMessage,
      clearMessages,
      setMessages
    }}>
      {children}
    </ConversationContext.Provider>
  )
}

export function useConversation() {
  const context = useContext(ConversationContext)
  if (context === undefined) {
    throw new Error('useConversation must be used within a ConversationProvider')
  }
  return context
}
