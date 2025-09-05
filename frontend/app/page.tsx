"use client"

import { useState } from "react"
import { Shield, Zap, FileText, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

const SAMPLE_VULNERABLE_CODE = `// Example vulnerable code for demonstration
function authenticateUser(username, password) {
  const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
  return database.query(query);
}

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const userData = getUserData(userId);
  res.json(userData);
});

// SQL injection vulnerability in line 3
// IDOR vulnerability in lines 7-10`

export default function Home() {
  const [code, setCode] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const handleAnalyze = async () => {
    if (!code.trim()) return
    
    setIsAnalyzing(true)
    
    // Store the code in sessionStorage and navigate to conversation
    sessionStorage.setItem('codeToAnalyze', code)
    window.location.href = "/conversation"
  }

  const handleSampleCode = () => {
    setCode(SAMPLE_VULNERABLE_CODE)
  }

  const handleClear = () => {
    setCode("")
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
        <div className="max-w-4xl mx-auto">
          <Card className="border-border">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span>Analyze Your Codebase</span>
              </CardTitle>
              <CardDescription>
                Paste your code for security analysis. Language auto-detected.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Code Editor */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Source Code</label>
                <div className="relative">
                  <textarea
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="// Paste your code here&#10;// Language auto-detected&#10;// Example:"
                    className="w-full h-96 p-4 font-mono text-sm bg-muted border border-input rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                    style={{ fontFamily: 'var(--font-geist-mono)' }}
                  />
                  <div className="absolute top-2 right-2 text-xs text-muted-foreground bg-background px-2 py-1 rounded">
                    {code.length} characters
                  </div>
                </div>
              </div>

              {/* Action Bar */}
              <div className="flex items-center justify-between pt-4 border-t border-border">
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleSampleCode}
                    disabled={isAnalyzing}
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    Sample Code
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleClear}
                    disabled={isAnalyzing}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Clear
                  </Button>
                </div>
                
                <Button
                  onClick={handleAnalyze}
                  disabled={!code.trim() || isAnalyzing}
                  className="min-w-32"
                >
                  {isAnalyzing ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Zap className="h-4 w-4 mr-2" />
                      Initiate Scan
                    </>
                  )}
                </Button>
              </div>

              {/* Info Box */}
              <div className="bg-muted/50 border border-border rounded-lg p-4">
                <div className="flex items-start space-x-3">
                  <Shield className="h-5 w-5 text-primary mt-0.5" />
                  <div className="space-y-1">
                    <h4 className="text-sm font-medium">Features</h4>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      <li>• OWASP Top 10 detection</li>
                      <li>• CVSS scoring</li>
                      <li>• CWE classification</li>
                      <li>• AI analysis</li>
                      <li>• Auto language detection</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}