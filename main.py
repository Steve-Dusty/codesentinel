from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import tempfile
import os
import json
import subprocess
from dotenv import load_dotenv
from typing import List, TypedDict, Optional
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.util import ClassNotFound
import asyncio


from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

app = FastAPI(title="CodeSentinel API", version="1.0.0")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_message(self, message: dict, websocket: WebSocket = None):
        print(f"📤 Sending WebSocket message: {message['type']} to {len(self.active_connections)} connections")
        if websocket:
            await websocket.send_text(json.dumps(message))
        else:

            dead_connections = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(json.dumps(message))
                    print(f"✅ Message sent successfully to connection")
                except Exception as e:
                    print(f"❌ Failed to send message: {e}")

                    dead_connections.append(connection)
            

            for dead_conn in dead_connections:
                if dead_conn in self.active_connections:
                    self.active_connections.remove(dead_conn)

manager = ConnectionManager()


load_dotenv()
os.getenv("GOOGLE_API_KEY")
model = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0.0, max_retries=0)
memory = MemorySaver()


class GraphState(TypedDict):
    messages: List[BaseMessage]
    current_chunk_index: int
    code_chunks: List[str]


investigator_prompt = ChatPromptTemplate.from_messages([
    ("system",
     """You are an expert security code reviewer named "Investigator". Your goal is to find security flaws in the code through detailed analysis and questioning.

**YOUR PERSONALITY:**
- You are thorough, methodical, and security-focused
- You think like a penetration tester and security auditor
- You ask probing questions to understand potential vulnerabilities
- You speak in a professional but conversational tone

**YOUR PROCESS:**
1. Review the code snippet provided in the conversation history
2. If you see a potential security flaw that has NOT yet been discussed, ask a detailed, specific question about it. Explain WHY you're concerned and what the potential risk might be. End your response with a question mark.
3. If all your previous questions about the current snippet have been answered and you find NO NEW flaws to discuss, you MUST respond with: 'I've completed my security review of this code chunk. No further security issues identified.'

**EXAMPLE RESPONSES:**
- "I'm concerned about this authentication logic. The password comparison appears to be using plain text, which could be vulnerable to timing attacks. How is the password hashing implemented?"
- "This SQL query construction looks suspicious. Are you using parameterized queries to prevent SQL injection? I see string concatenation that could be dangerous."
- "I've completed my security review of this code chunk. No further security issues identified."
"""),
    ("placeholder", "{messages}")
])

interrogator_prompt = ChatPromptTemplate.from_template(
    """You are a senior developer named "Interrogator". Your job is to answer the security reviewer's questions and provide context about the code.

**YOUR PERSONALITY:**
- You are knowledgeable, defensive of your code, but open to security concerns
- You provide detailed technical explanations
- You think like a developer who wants to understand and fix security issues
- You speak in a professional, technical tone

**YOUR ROLE:**
Answer the security reviewer's question about the CURRENT CHUNK of code. Use the FULL CODEBASE for context if needed. Provide detailed explanations about how the code works, what security measures are in place, or acknowledge potential issues.

**RESPONSE STYLE:**
- Be thorough and technical in your explanations
- If there's a security concern, either explain why it's not an issue or acknowledge the problem
- Reference specific parts of the code when relevant
- Keep responses conversational but informative

--- FULL CODEBASE ---
{full_code}
--- CURRENT CHUNK ---
{current_chunk}
--- SECURITY REVIEWER'S QUESTION ---
{question}

Please provide a detailed response to the security reviewer's question.
"""
)

analyst_prompt = ChatPromptTemplate.from_template(
    """You are a Principal Security Engineer acting as an automated vulnerability analysis tool.
Your mission is to synthesize a raw conversation transcript into a structured security report in JSON format.
Your output MUST be a single, valid JSON object and nothing else.

**JSON OUTPUT STRUCTURE:**
You must generate a JSON object with a top-level `summary` object and a `vulnerabilities` array.
For each confirmed vulnerability in the transcript, create an object in the `vulnerabilities` array with the following fields:

- `title`: A concise, one-sentence summary of the flaw.
- `cwe`: The most appropriate CWE number (e.g., "CWE-798").
- `owasp_category`: The most relevant OWASP Top 10 2021 category (e.g., "A01:2021-Broken Access Control").
- `cvss_score`: An estimated CVSS 3.1 Base Score from 0.0 to 10.0.
- `severity`: A severity rating based on the CVSS score (Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9).
- `code_snippet`: The exact lines of code that contain the vulnerability.
- `explanation_for_pdf`: A clear, detailed explanation of the security risk, including a deep dive into the associated CWE, suitable for a formal PDF report.
- `recommendation_for_pdf`: A specific, actionable recommendation for how to fix the flaw, suitable for a formal PDF report.

After detailing all vulnerabilities, provide an overall assessment in the `summary` object with the following fields:
- `overall_cvss_score`: The highest CVSS score from the vulnerabilities, or 0.0 if none.
- `overall_severity`: The severity corresponding to the overall_cvss_score (Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9, None: 0.0).
- `unique_owasp_categories`: An array of unique OWASP categories from the vulnerabilities. This is an array dictionary, withq a rating from A to F for each overall category. 
- `overall_score`: A letter grade from A (Excellent) to F (Critical Failure).
- `summary_text`: A 1-2 sentence summary of the code's security posture.

If no issues were found, the `vulnerabilities` array should be empty, overall_cvss_score should be 0.0, overall_severity "None", and unique_owasp_categories an empty array.

**BEGIN ANALYSIS OF THE FOLLOWING TRANSCRIPT:**
---
{conversation_history}
---
"""
)


investigator_runnable = investigator_prompt | model
interrogator_runnable = interrogator_prompt | model
analyst_runnable = analyst_prompt | model

class CodeRequest(BaseModel):
    code: str
    language: Optional[str] = None


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    print("🔌 New WebSocket connection attempt")
    await manager.connect(websocket)
    print(f"✅ WebSocket connected! Total connections: {len(manager.active_connections)}")
    

    await manager.send_message({
        "type": "connection_established",
        "message": "WebSocket connection established successfully",
        "timestamp": asyncio.get_event_loop().time()
    })
    
    try:
        while True:

            try:

                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                print(f"📨 Received from client: {data}")
                

                try:
                    import json
                    message = json.loads(data)
                    if message.get('type') == 'heartbeat':
                        print("💓 Received heartbeat from client")
                        continue
                except (json.JSONDecodeError, KeyError):
                    pass
                    
            except asyncio.TimeoutError:

                try:
                    await websocket.ping()
                    print("🏓 Sent ping to keep connection alive")
                except Exception as ping_error:
                    print(f"⚠️ Ping failed: {ping_error}")
                    break
            except Exception as e:
                print(f"⚠️ WebSocket receive error: {e}")
                break
    except WebSocketDisconnect:
        print("🔌 WebSocket disconnected by client")
        manager.disconnect(websocket)
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
        manager.disconnect(websocket)
        print(f"📊 Remaining connections: {len(manager.active_connections)}")

async def run_ai_analysis(file_path: str):
    """Run AI analysis on the specified file path - integrated from snippet.py"""
    print(f"📁 Loading and splitting: {file_path}")
    

    print(f"🔗 Sending analysis_started message to {len(manager.active_connections)} connections")
    await manager.send_message({
        "type": "analysis_started",
        "message": "Starting security analysis...",
        "timestamp": asyncio.get_event_loop().time()
    })
    print(f"✅ analysis_started message sent successfully")
    

    loader = GenericLoader.from_filesystem(
        path=file_path,
        parser=LanguageParser(parser_threshold=10)
    )
    documents = loader.load()
    code_chunks = [doc.page_content for doc in documents]
    print(f"--- Codebase split into {len(code_chunks)} chunks. ---")
    

    await manager.send_message({
        "type": "chunks_loaded",
        "message": f"Code split into {len(code_chunks)} chunks for analysis",
        "chunk_count": len(code_chunks),
        "timestamp": asyncio.get_event_loop().time()
    })
    

    def interrogator_node(state: GraphState):
        print("--- Calling Interrogator ---")
        current_idx = state['current_chunk_index']
        current_chunk = state['code_chunks'][current_idx]
        if len(state['messages']) == 0:
            presentation_text = f"""I'm presenting this code chunk for security analysis:

```python
{current_chunk}
```

This is chunk {current_idx + 1} of {len(state['code_chunks'])} in the codebase. Please conduct a thorough security review and identify any potential vulnerabilities or security concerns."""
            
            presentation = HumanMessage(content=f"**Interrogator**: {presentation_text}")
            return {"messages": [presentation]}
        else:
            question = state['messages'][-1].content
            response_ai = interrogator_runnable.invoke({
                "full_code": "\n---\n".join(state['code_chunks']),
                "current_chunk": current_chunk,
                "question": question
            })
            
            response_human = HumanMessage(content=f"**Interrogator**: {response_ai.content}")
            return {"messages": [response_human]}

    def investigator_node(state: GraphState):
        print("--- Calling Investigator ---")
        response = investigator_runnable.invoke({"messages": state['messages']})
        

        investigator_message = AIMessage(content=f"**Investigator**: {response.content}")
        return {"messages": [investigator_message]}

    def update_index_node(state: GraphState):

        print("CHUNK COMPLETE, MOVING TO NEXT CHUNK")

        current_idx = state['current_chunk_index']
        return {"current_chunk_index": current_idx + 1, "messages": []}

    def router_node(state: GraphState):
        print("--- Calling Router ---")
        last_message = state['messages'][-1].content
        if last_message.strip().endswith('?'):
            print("Router decision: 'continue' (question found)")
            return "interrogator"
        else:
            print("Router decision: 'move_on' (no question found)")
            current_idx = state['current_chunk_index']
            if current_idx + 1 >= len(state['code_chunks']):
                print("Router: All chunks analyzed. Ending workflow.")
                return "end"
            else:
                return "update_index"

    # Build and compile the discovery graph
    graph_builder = StateGraph(GraphState)
    graph_builder.add_node("interrogator", interrogator_node)
    graph_builder.add_node("investigator", investigator_node)
    graph_builder.add_node("update_index", update_index_node)
    graph_builder.set_entry_point("interrogator")
    graph_builder.add_edge("interrogator", "investigator")
    graph_builder.add_edge("update_index", "interrogator")
    graph_builder.add_conditional_edges(
        "investigator", router_node, {
            "interrogator": "interrogator",
            "update_index": "update_index",
            "end": END
        }
    )
    discovery_graph = graph_builder.compile(checkpointer=memory)

    # Run the analysis
    print("\n--- STARTING PHASE 1: DISCOVERY ---")
    initial_state = {"messages": [], "code_chunks": code_chunks, "current_chunk_index": 0}
    config = {
        "configurable": {"thread_id": "dashboard-ready-session-v1"},
        "recursion_limit": 500
    }
    full_conversation_history = []
    
    for event in discovery_graph.stream(initial_state, config=config):
        if "messages" in event.get('interrogator', {}):
            messages = event['interrogator']["messages"]
            full_conversation_history.extend(messages)
            
            # Send WebSocket message for interrogator
            for msg in messages:
                if isinstance(msg, HumanMessage):
                    content = msg.content.replace("**Interrogator**: ", "")
                    
                    # Print to terminal
                    print(f"\n🔵 INTERROGATOR: {content}")
                    print("-" * 80)
                    
                    # Send immediately
                    await manager.send_message({
                        "type": "interrogator_message",
                        "agent": "Interrogator",
                        "message": content,
                        "timestamp": asyncio.get_event_loop().time()
                    })
                    print(f"📤 Sent interrogator message to {len(manager.active_connections)} connections")
                    
                    # Small delay to ensure message is sent
                    await asyncio.sleep(0.1)
                    
        if "messages" in event.get('investigator', {}):
            messages = event['investigator']["messages"]
            full_conversation_history.extend(messages)
            
            # Send WebSocket message for investigator
            for msg in messages:
                if isinstance(msg, AIMessage):
                    content = msg.content.replace("**Investigator**: ", "")
                    
                    # Print to terminal
                    print(f"\n🔴 INVESTIGATOR: {content}")
                    print("-" * 80)
                    
                    # Send immediately
                    await manager.send_message({
                        "type": "investigator_message",
                        "agent": "Investigator",
                        "message": content,
                        "timestamp": asyncio.get_event_loop().time()
                    })
                    print(f"📤 Sent investigator message to {len(manager.active_connections)} connections")
                    
                    # Small delay to ensure message is sent
                    await asyncio.sleep(0.1)
                    
        if "current_chunk_index" in event.get('update_index', {}):
            # Send chunk completion message
            new_index = event['update_index']["current_chunk_index"]
            
            # Print to terminal
            print(f"\n✅ CHUNK {new_index} COMPLETE - Moving to next chunk...")
            print("=" * 80)
            
            await manager.send_message({
                "type": "chunk_complete",
                "message": f"Chunk {new_index} analysis complete. Moving to next chunk...",
                "chunk_number": new_index,
                "timestamp": asyncio.get_event_loop().time()
            })
            
    print("\n--- PHASE 1: DISCOVERY COMPLETE ---")
    
    print("\n--- STARTING PHASE 2: SYNTHESIS ---")
    transcript = ""
    for msg in full_conversation_history:
        if isinstance(msg, HumanMessage):
            transcript += f"{msg.content}\n\n"
        elif isinstance(msg, AIMessage):
            transcript += f"{msg.content}\n\n"
    
    # Send referee message - analysis complete
    referee_msg = "Security analysis complete! All code chunks have been thoroughly reviewed by our security experts. Generating final report..."
    
    # Print to terminal
    print(f"\n🟣 REFEREE: {referee_msg}")
    print("=" * 80)
    
    await manager.send_message({
        "type": "referee_message",
        "agent": "Referee",
        "message": referee_msg,
        "timestamp": asyncio.get_event_loop().time()
    })
    
    print("\n--- CALLING ANALYST AGENT TO GENERATE FINAL REPORT ---")
    print(f"📝 Transcript length: {len(transcript)} characters")
    print(f"📝 Transcript preview: {transcript[:200]}...")
    print(f"🔗 Active WebSocket connections: {len(manager.active_connections)}")
    
    try:
        final_report_str = analyst_runnable.invoke({"conversation_history": transcript}).content
        print(f"✅ Analyst response received: {len(final_report_str)} characters")
        print(f"🔗 Active WebSocket connections after analyst: {len(manager.active_connections)}")
    except Exception as e:
        print(f"❌ Analyst failed: {e}")
        print(f"🔗 Active WebSocket connections after analyst error: {len(manager.active_connections)}")
        raise e

    # Clean up the JSON
    if final_report_str.startswith("```json"):
        final_report_str = final_report_str[7:]
    if final_report_str.startswith("```"):
        final_report_str = final_report_str[3:]
    if final_report_str.endswith("```"):
        final_report_str = final_report_str[:-3]
    
    final_report_str = final_report_str.strip()
    
    # Fix common JSON issues
    import re
    final_report_str = re.sub(r',(\s*[}\]])', r'\1', final_report_str)

    # Parse the JSON
    try:
        report_json = json.loads(final_report_str)
        print("✅ JSON report generated successfully!")
        
        # Write to final_report.json (like snippet.py does)
        with open("final_report.json", "w") as f:
            f.write(final_report_str)
        print("💾 Report saved to final_report.json")
        
        # --- PHASE 3: GENERATE LATEX AND PDF (same as snippet.py) ---
        print("\n--- STARTING PHASE 3: LATEX AND PDF GENERATION ---")
        
        def escape_latex(text):
            """Escape special LaTeX characters."""
            chars = {
                '&': r'\&',
                '%': r'\%',
                '$': r'\$',
                '#': r'\#',
                '_': r'\_',
                '{': r'\{',
                '}': r'\}',
                '~': r'\textasciitilde{}',
                '^': r'\textasciicircum{}',
                '\\': r'\textbackslash{}',
            }
            return ''.join(chars.get(c, c) for c in text)
        
        # Build LaTeX document string
        owasp_categories = report_json['summary']['unique_owasp_categories']
        if owasp_categories:
            # Extract the keys from the list of dictionaries
            category_names = [list(cat.keys())[0] for cat in owasp_categories if cat and list(cat.keys())]
            owasp_categories_str = ', '.join(category_names)
        else:
            owasp_categories_str = 'None'
        
        latex = r"""
\documentclass{article}
\usepackage[margin=1in]{geometry}
\usepackage{listings}
\usepackage{color}
\usepackage{hyperref}
\usepackage{longtable}
\usepackage{adjustbox}
\definecolor{codegreen}{rgb}{0,0.6,0}
\definecolor{codegray}{rgb}{0.5,0.5,0.5}
\definecolor{codepurple}{rgb}{0.58,0,0.82}
\definecolor{backcolour}{rgb}{0.95,0.95,0.92}

\lstdefinestyle{mystyle}{
    backgroundcolor=\color{backcolour},   
    commentstyle=\color{codegreen},
    keywordstyle=\color{blue},
    numberstyle=\tiny\color{codegray},
    stringstyle=\color{codepurple},
    basicstyle=\ttfamily\footnotesize,
    breakatwhitespace=false,         
    breaklines=true,                 
    captionpos=b,                    
    keepspaces=true,                 
    numbers=left,                    
    numbersep=5pt,                  
    showspaces=false,                
    showstringspaces=false,
    showtabs=false,                  
    tabsize=2
}

\lstset{style=mystyle}

\title{Security Analysis Report}
\author{CodeSentinel AI Security Analysis}
\date{\today}

\begin{document}

\maketitle

\tableofcontents
\newpage

\section{Executive Summary}
\textbf{Overall Security Score:} """ + escape_latex(report_json['summary']['overall_score']) + r""" \\
\textbf{Overall CVSS Score:} """ + str(report_json['summary']['overall_cvss_score']) + r""" (""" + escape_latex(report_json['summary']['overall_severity']) + r""") \\
\textbf{OWASP Categories Affected:} """ + escape_latex(owasp_categories_str) + r""" \\
\textbf{Summary:} """ + escape_latex(report_json['summary']['summary_text']) + r"""

\section{Detailed Vulnerabilities}
""" 
        
        if not report_json['vulnerabilities']:
            latex += r"No vulnerabilities were identified in the code analysis."
        else:
            latex += r"""
\begin{adjustbox}{width=\textwidth,center}
\begin{longtable}{|l|p{10cm}|}
\hline
\textbf{Title} & \textbf{Details} \\
\hline
\endhead
"""
            for vuln in report_json['vulnerabilities']:
                details = r"""
\textbf{CWE:} """ + escape_latex(vuln['cwe']) + r""" \\
\textbf{OWASP Category:} """ + escape_latex(vuln['owasp_category']) + r""" \\
\textbf{CVSS Score:} """ + str(vuln['cvss_score']) + r""" \\
\textbf{Severity:} """ + escape_latex(vuln['severity']) + r""" \\

\textbf{Explanation:} \\
""" + escape_latex(vuln['explanation_for_pdf']) + r""" \\

\textbf{Recommendation:} \\
""" + escape_latex(vuln['recommendation_for_pdf']) + r""" \\

\textbf{Code Snippet:} \\
\lstset{language=Python}
\begin{lstlisting}
""" + escape_latex(vuln['code_snippet']) + r"""
\end{lstlisting}
"""
                latex += escape_latex(vuln['title']) + " & " + details + r""" \\
\hline
"""
            latex += r"""
\end{longtable}
\end{adjustbox}
"""
        
        latex += r"""

\end{document}
"""
        
        # Write LaTeX to file
        tex_file = "report.tex"
        with open(tex_file, 'w') as f:
            f.write(latex)
        print(f"--- LaTeX written to {tex_file} ---")
        
        # Compile to PDF using pdflatex (run twice for stability)
        pdf_file = "report.pdf"
        subprocess.call(['pdflatex', '-interaction=nonstopmode', tex_file])
        subprocess.call(['pdflatex', '-interaction=nonstopmode', tex_file])
        print(f"--- PDF generated at {pdf_file} ---")
        
        print("\n--- PHASE 3 COMPLETE ---")
        
        # Send final report message
        final_msg = "Final security report generated successfully!"
        
        # Print to terminal
        print(f"\n🎉 ANALYSIS COMPLETE: {final_msg}")
        print("=" * 80)
        print("📊 FINAL REPORT SUMMARY:")
        print(f"   Overall Score: {report_json.get('summary', {}).get('overall_score', 'N/A')}")
        print(f"   CVSS Score: {report_json.get('summary', {}).get('overall_cvss_score', 'N/A')}")
        print(f"   Vulnerabilities Found: {len(report_json.get('vulnerabilities', []))}")
        print("=" * 80)
        
        print(f"📤 Sending analysis_complete message to {len(manager.active_connections)} connections")
        await manager.send_message({
            "type": "analysis_complete",
            "message": final_msg,
            "report": report_json,
            "timestamp": asyncio.get_event_loop().time()
        })
        print("✅ analysis_complete message sent successfully")
        
        return report_json
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing error: {e}")
        
        # Send error message
        await manager.send_message({
            "type": "analysis_error",
            "message": "Failed to generate final report",
            "error": str(e),
            "timestamp": asyncio.get_event_loop().time()
        })
        
        return {"error": "Failed to parse analysis report"}
    except Exception as e:
        print(f"❌ CRITICAL ANALYSIS ERROR: {e}")
        import traceback
        traceback.print_exc()
        
        # Send critical error message
        await manager.send_message({
            "type": "analysis_error",
            "message": f"Analysis failed with critical error: {str(e)}",
            "error": str(e),
            "timestamp": asyncio.get_event_loop().time()
        })
        
        return {"error": f"Analysis failed: {str(e)}"}

@app.post("/api/analyze")
async def analyze_code(request: CodeRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty")
    
    # Detect language using Pygments
    print(f"\n--- Starting Language Detection ---")
    try:
        lexer = guess_lexer(request.code)
        detected_language = lexer.aliases[0] if lexer.aliases else lexer.name.lower()
        print(f"✅ Language detected: {detected_language}")
    except Exception as e:
        print(f"⚠️ Language detection failed: {e}")
        detected_language = "text"

    # Map language to file extension
    language_extensions = {
        'python': '.py', 'py': '.py',
        'javascript': '.js', 'js': '.js',
        'typescript': '.ts', 'ts': '.ts',
        'java': '.java',
        'c': '.c',
        'cpp': '.cpp', 'c++': '.cpp',
        'csharp': '.cs', 'c#': '.cs',
        'php': '.php',
        'go': '.go', 'golang': '.go',
        'rust': '.rs',
        'ruby': '.rb',
        'swift': '.swift',
        'kotlin': '.kt',
        'html': '.html',
        'css': '.css',
        'sql': '.sql',
        'bash': '.sh', 'sh': '.sh', 'shell': '.sh',
        'powershell': '.ps1', 'ps1': '.ps1',
        'gdscript': '.gd',
        'text': '.txt'
    }

    file_extension = language_extensions.get(detected_language, '.txt')
    print(f"📄 File extension: {file_extension}")
    
    # Create codes directory and file
    codes_dir = "codes"
    os.makedirs(codes_dir, exist_ok=True)
    
    file_path = os.path.join(codes_dir, f"code_{os.urandom(8).hex()}{file_extension}")
    with open(file_path, 'w') as f:
        f.write(request.code)
    print(f"💾 File created: {file_path}")
    
    # Run AI analysis on the created file
    print(f"🤖 Starting AI analysis on: {file_path}")
    print(f"🔗 Active WebSocket connections before analysis: {len(manager.active_connections)}")
    analysis_result = await run_ai_analysis(file_path)
    print(f"🔗 Active WebSocket connections after analysis: {len(manager.active_connections)}")
    print(f"📊 Analysis result: {analysis_result}")
    
    return {
        "status": "success",
        "message": "Code received and processed",
        "detected_language": detected_language,
        "file_path": file_path,
        "analysis_result": analysis_result
    }

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/report")
async def get_report():
    """Get the latest analysis report from final_report.json"""
    try:
        with open("final_report.json", "r") as f:
            report_data = json.load(f)
        return report_data
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No analysis report found")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid report format")

@app.get("/api/download-pdf")
async def download_pdf():
    """Download the generated PDF report"""
    pdf_path = "report.pdf"
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found. Please run an analysis first.")
    
    return FileResponse(
        path=pdf_path,
        filename="security_analysis_report.pdf",
        media_type="application/pdf"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)