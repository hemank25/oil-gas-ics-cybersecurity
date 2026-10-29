"""
architecture_case_study.py
==========================
Refinery ICS System Architecture, Stuxnet Deep-Dive Case Study & Ethics.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: OT Cybersecurity Engineer & Machine Learning Specialist

Key Sections:
1. Interactive Purdue Enterprise Reference Architecture Schematic (Levels 0-3.5).
2. End-to-End Cyber-Physical Data Pipeline Architecture.
3. Comprehensive Historical Case Study: The 2010 Stuxnet Centrifuge Sabotage.
4. Translation of Stuxnet Defensive Lessons to Modern AI Anomaly Detection.
5. ICS Cybersecurity Ethics, Safety Mandates & Responsible Disclosure.
"""

import streamlit as st

def generate_architecture_svg() -> str:
    """Generate crisp, high-DPI SVG diagram of the complete cyber-physical architecture."""
    width = 720
    height = 420

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="auto" style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:6px; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
    <defs>
        <marker id="flow-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#2563eb" />
        </marker>
        <marker id="data-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#16a34a" />
        </marker>
        <marker id="sec-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#dc2626" />
        </marker>
    </defs>

    <!-- LEVEL 3.5: DMZ & PERIMETER -->
    <rect x="20" y="15" width="680" height="75" rx="5" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1.2" stroke-dasharray="4,4"/>
    <text x="32" y="32" font-size="10" font-weight="700" fill="#475569">PURDUE LEVEL 3.5 : DMZ &amp; PERIMETER SECURITY GATEWAY</text>
    
    <!-- Firewall N-01 Box -->
    <rect x="260" y="40" width="200" height="40" rx="4" fill="#ffffff" stroke="#2563eb" stroke-width="2"/>
    <text x="360" y="58" font-size="10" font-weight="700" fill="#1e293b" text-anchor="middle">N-01: Industrial Firewall (DPI)</text>
    <text x="360" y="70" font-size="8.5" fill="#64748b" text-anchor="middle" font-family="monospace">Modbus DPI | Stateful Inspection | VPN</text>

    <!-- LEVEL 2: SUPERVISORY OT SUBNET -->
    <rect x="20" y="110" width="680" height="110" rx="5" fill="#ffffff" stroke="#94a3b8" stroke-width="1.2" stroke-dasharray="4,4"/>
    <text x="32" y="126" font-size="10" font-weight="700" fill="#475569">PURDUE LEVEL 2 : OT SUPERVISORY CONTROL &amp; ENGINEERING (192.168.10.0/24)</text>

    <!-- HMI-01 -->
    <rect x="40" y="145" width="180" height="60" rx="4" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
    <text x="130" y="165" font-size="10" font-weight="700" fill="#0f172a" text-anchor="middle">H-01: Operator HMI</text>
    <text x="130" y="178" font-size="8.5" fill="#475569" text-anchor="middle">Graphics &amp; Alarms Console</text>
    <text x="130" y="192" font-size="8" fill="#d97706" text-anchor="middle">VAPT-2026-002: Insecure VNC</text>

    <!-- SCADA Host C-01 -->
    <rect x="270" y="145" width="180" height="60" rx="4" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
    <text x="360" y="165" font-size="10" font-weight="700" fill="#1d4ed8" text-anchor="middle">C-01: SCADA Server</text>
    <text x="360" y="178" font-size="8.5" fill="#1e40af" text-anchor="middle">Historian Collector &amp; OPC UA</text>
    <text x="360" y="192" font-size="8" fill="#15803d" text-anchor="middle">Polling Master (1.0 Hz)</text>

    <!-- EWS-01 -->
    <rect x="500" y="145" width="180" height="60" rx="4" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
    <text x="590" y="165" font-size="10" font-weight="700" fill="#0f172a" text-anchor="middle">E-01: Engineering Station</text>
    <text x="590" y="178" font-size="8.5" fill="#475569" text-anchor="middle">PLC Programming &amp; Logic</text>
    <text x="590" y="192" font-size="8" fill="#d97706" text-anchor="middle">VAPT-2026-003: SMB Signing</text>

    <!-- LEVEL 1/0: FIELD CONTROLLERS & PROCESS UNITS -->
    <rect x="20" y="240" width="680" height="165" rx="5" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1.2" stroke-dasharray="4,4"/>
    <text x="32" y="256" font-size="10" font-weight="700" fill="#475569">PURDUE LEVEL 1/0 : BASIC PROCESS CONTROL &amp; REFINERY FIELD INSTRUMENTATION</text>

    <!-- Field Units: U-01, U-02, U-03, U-04, U-05 -->
    <rect x="40" y="275" width="115" height="115" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
    <text x="97" y="295" font-size="9" font-weight="700" fill="#0f172a" text-anchor="middle">U-01: Crude Feed</text>
    <text x="97" y="310" font-size="8" fill="#475569" text-anchor="middle">PLC-01-A (p:502)</text>
    <text x="97" y="325" font-size="7.5" fill="#64748b" text-anchor="middle">P1_PCV01D / PIT01</text>
    <text x="97" y="340" font-size="7.5" fill="#16a34a" text-anchor="middle">Fractionation Column</text>

    <rect x="175" y="275" width="115" height="115" rx="4" fill="#fef2f2" stroke="#dc2626" stroke-width="1.5"/>
    <text x="232" y="295" font-size="9" font-weight="700" fill="#991b1b" text-anchor="middle">U-02: Steam Boiler</text>
    <text x="232" y="310" font-size="8" fill="#b91c1c" text-anchor="middle">PLC-01 (Modbus/TCP)</text>
    <text x="232" y="325" font-size="7.5" fill="#64748b" text-anchor="middle">P1_LIT01 / TIT02</text>
    <text x="232" y="340" font-size="7.5" fill="#dc2626" font-weight="700" text-anchor="middle">VAPT-2026-001 (CRIT)</text>

    <rect x="310" y="275" width="115" height="115" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
    <text x="367" y="295" font-size="9" font-weight="700" fill="#0f172a" text-anchor="middle">U-03: Storage Tanks</text>
    <text x="367" y="310" font-size="8" fill="#475569" text-anchor="middle">PLC-02 (DNP3/IP)</text>
    <text x="367" y="325" font-size="7.5" fill="#64748b" text-anchor="middle">P2_24Vdc / OnOff</text>
    <text x="367" y="340" font-size="7.5" fill="#16a34a" text-anchor="middle">Blending Manifold</text>

    <rect x="445" y="275" width="115" height="115" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
    <text x="502" y="295" font-size="9" font-weight="700" fill="#0f172a" text-anchor="middle">U-04: Turbines</text>
    <text x="502" y="310" font-size="8" fill="#475569" text-anchor="middle">PLC-04 (S7comm)</text>
    <text x="502" y="325" font-size="7.5" fill="#64748b" text-anchor="middle">P4_ST_GOV / TT01</text>
    <text x="502" y="340" font-size="7.5" fill="#0284c7" text-anchor="middle">Governor Drive Hall</text>

    <rect x="580" y="275" width="105" height="115" rx="4" fill="#f8fafc" stroke="#64748b" stroke-width="1.2"/>
    <text x="632" y="295" font-size="9" font-weight="700" fill="#334155" text-anchor="middle">U-05: Safety SIS</text>
    <text x="632" y="310" font-size="8" fill="#475569" text-anchor="middle">TMR-SIS-01</text>
    <text x="632" y="325" font-size="7.5" fill="#64748b" text-anchor="middle">P2_Emerg / ESD</text>
    <text x="632" y="340" font-size="7.5" fill="#059669" font-weight="700" text-anchor="middle">SIL-3 Hardwired</text>

    <!-- Communication arrows -->
    <line x1="360" y1="80" x2="360" y2="145" stroke="#2563eb" stroke-width="2" marker-end="url(#flow-arrow)"/>
    <line x1="220" y1="175" x2="270" y2="175" stroke="#16a34a" stroke-width="2" marker-end="url(#data-arrow)"/>
    <line x1="500" y1="175" x2="450" y2="175" stroke="#64748b" stroke-width="2" stroke-dasharray="3,2"/>
    <line x1="360" y1="205" x2="360" y2="245" stroke="#16a34a" stroke-width="2.5" marker-end="url(#data-arrow)"/>
</svg>"""

def render_system_architecture_page():
    """Render the full Architecture, Stuxnet Case Study and Ethics Workstation."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>🏛️ System Architecture, Stuxnet Case Study &amp; Ethics</h2>
            <p>Purdue Reference Model alignment, end-to-end data pipelines, historical Stuxnet analysis, and safety mandates.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    arch_tabs = st.tabs([
        "🏭 Purdue Architecture Model",
        "📡 Cyber-Physical Pipeline & Defense-in-Depth",
        "📚 Stuxnet Case Study Deep-Dive",
        "⚖️ Ethics, Safety & Responsible Disclosure"
    ])

    # =========================================================================
    # TAB 1: PURDUE ARCHITECTURE MODEL
    # =========================================================================
    with arch_tabs[0]:
        st.markdown("### 🏭 Purdue Enterprise Reference Architecture (ISA-95 / ISA/IEC 62443)")
        st.caption(
            "Hierarchical network segmentation isolating physical process control loops from enterprise business systems:"
        )

        svg_markup = generate_architecture_svg()
        st.components.v1.html(svg_markup, height=440, scrolling=False)

        st.markdown(
            """
            #### 🏢 Architectural Layer Decomposition:
            - **Level 3.5: Demilitarized Zone (DMZ) & Boundary**:
              - Houses Industrial Next-Gen Firewall (`N-01`) enforcing Deep Packet Inspection (DPI) on Modbus/TCP and S7comm. Terminates corporate IT replication.
            - **Level 2: OT Supervisory Control & Engineering Subnet (`192.168.10.0/24`)**:
              - Houses Supervisory SCADA Server (`C-01`), Operator HMI Console (`H-01`), and Engineering Workstation (`E-01`). Polling rate: 1.0 Hz.
            - **Level 1: Basic Process Control System (BPCS)**:
              - Programmable Logic Controllers (`PLC-01-A`, `PLC-01`, `PLC-02`, `PLC-04`) executing cyclic ladder logic.
            - **Level 0: Physical Field Instrumentation**:
              - Primary transmitters (piezoelectric pressure, RTD temperatures, drum levels) and pneumatic control valves (`PCV01D`, `FCV01D`).
            - **Safety Instrumented System (SIS - SIL-3)**:
              - Independent Triple Modular Redundant controller (`TMR-SIS-01`) on an isolated hardwired bus with emergency trip contacts.
            """
        )

    # =========================================================================
    # TAB 2: CYBER-PHYSICAL PIPELINE & DEFENSE-IN-DEPTH
    # =========================================================================
    with arch_tabs[1]:
        st.markdown("### 📡 End-to-End Cyber-Physical Data Pipeline")
        st.caption("How field measurements flow from physical instrumentation into the dual-paradigm detection engine:")

        st.markdown(
            """
            ```
            [ Field Sensors & Actuators (Level 0) ]
                            │  4-20 mA Analog & Digital I/O
                            ▼
            [ Programmable Logic Controllers (Level 1) ]
                            │  Modbus/TCP, S7comm, DNP3 Telemetry
                            ▼
            [ Supervisory SCADA Server C-01 (Level 2) ]
                            │  Cyclic Ingest (1.0 Hz, 86 Tags)
                            ▼
            [ Preprocessing Pipeline (StandardScaler) ]
                            │  Zero-Mean Scaling Fitted on Normal Baseline
                            ▼
            ┌───────────────────────────────────────────────────────────┐
            │         DUAL-PARADIGM AI INFERENCE ENGINE                │
            │                                                           │
            │   Layer 1: Statistical Physics Limit (>4σ Deviation)      │
            │   Layer 2: Unsupervised Isolation Forest (Thresh: +0.0132)│
            │   Layer 3: Supervised Random Forest Signature Classifier  │
            └───────────────────────────────────────────────────────────┘
                            │
                            ▼
            [ CyberPhysicalCorrelator & Alert System ]
                            │  Cross-Correlates VAPT Findings + Alerts
                            ▼
            [ Operator HMI (H-01) & Incident Management Queue ]
               ⚠️ Note: Automated plant trip is strictly INHIBITED.
            ```
            """
        )

        st.markdown(
            """
            #### 🛡️ Defense-in-Depth Principle:
            - **Separation of Concerns**: Network-layer threats (unauthorized Modbus function codes, reconnaissance scans) are evaluated at the network inspection conduit. Physical anomalies (pressure spikes, valve manipulation) are evaluated by the continuous multivariate ML engine.
            - **Correlation Synthesis**: An alert elevates to **`CRITICAL: COORDINATED CYBER-PHYSICAL ATTACK`** only when an unauthorized network packet is temporally followed by a physical anomaly.
            """
        )

    # =========================================================================
    # TAB 3: STUXNET CASE STUDY DEEP-DIVE
    # =========================================================================
    with arch_tabs[2]:
        st.markdown("### 📚 Comprehensive Case Study: The 2010 Stuxnet Centrifuge Sabotage")
        st.caption("Detailed historical analysis of the world's first documented cyber warfare weapon engineered to cause physical destruction:")

        col_stux1, col_stux2 = st.columns([1.5, 1])

        with col_stux1:
            st.markdown(
                """
                #### 1. Attack Lifecycle & Mechanics
                - **Target**: Iranian gas centrifuges utilized for uranium enrichment at the Natanz enrichment facility.
                - **Air-Gap Crossing**: Traversed physical air-gaps via infected USB thumb drives introduced by third-party industrial contractors.
                - **Zero-Day Arsenal**: Leveraged 4 distinct Microsoft Windows zero-day vulnerabilities (including `CVE-2010-2568` LNK shortcut execution and Print Spooler RCE) signed with stolen legitimate certificates from Realtek and JMicron.
                - **Surgical Fingerprinting**: Specifically searched for Siemens **SIMATIC WinCC / Step 7** engineering software connected to **Siemens S7-300 PLCs** (CPU 315-2 and CPU 317) driving Variable Frequency Drives (VFDs) from Fararo Paya and Vacon.
                - **Physical Sabotage**: Periodically altered rotor speeds from normal **1,410 Hz** down to **2 Hz**, and subsequently up to **1,064 Hz**, inducing resonant mechanical fatigue and centrifuge destruction.
                - **Man-in-the-Middle (MitM) Covert Sensor Replay**: Recorded 21 seconds of normal telemetry and continuously replayed it back to the SCADA HMI so operators saw nominal green gauges while equipment tore itself apart physically.
                """
            )

        with col_stux2:
            st.markdown(
                """
                <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:4px; padding:12px;">
                    <div style="font-size:11px; font-weight:700; color:#64748b;">ACADEMIC DISCLAIMER</div>
                    <div style="font-size:12px; color:#1e293b; margin-top:4px;">
                        This case study analyzes documented historical sources. Our university project does <b>NOT</b> reproduce Stuxnet or deploy destructive zero-day payloads.
                        <br><br>
                        Instead, we model its operational mechanics (unauthorized PLC writes, sensor feedback spoofing, and resonant overspeed) to prove the defensive efficacy of AI multivariate anomaly detection.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("---")
        st.markdown("#### 🛡️ How Our AI Framework Solves Stuxnet-Style Attack Vectors:")
        
        comp_df = pd.DataFrame([
            {
                "Stuxnet Attack Phase": "Air-Gap Ingress & Lateral Spread",
                "Historical Natanz Vulnerability": "Unmanaged USB media execution on engineering stations",
                "Our Defensive Countermeasure": "Student 1 (VAPT): Finding VAPT-2026-003 enforces Windows GPO USB execution blocks and mandatory SMB signing on EWS-01."
            },
            {
                "Stuxnet Attack Phase": "Covert PLC Register Override",
                "Historical Natanz Vulnerability": "Unauthenticated S7comm / Modbus ladder logic block replacements",
                "Our Defensive Countermeasure": "Student 3 (Simulation): Deterministic replay of unauthorized register writes in safe isolated lab."
            },
            {
                "Stuxnet Attack Phase": "MitM Sensor Replay (21s Loop)",
                "Historical Natanz Vulnerability": "Single-loop threshold alarms fooled by recorded nominal sensor values",
                "Our Defensive Countermeasure": "Student 2 (AI Lead): Isolation Forest evaluates 86-tag cross-covariance simultaneously. If valve demand changes while pressure remains flat, joint covariance breaks down, triggering anomaly alert."
            },
            {
                "Stuxnet Attack Phase": "Operator Desensitization",
                "Historical Natanz Vulnerability": "Blind trust in SCADA HMI without independent cross-correlation",
                "Our Defensive Countermeasure": "Human-in-the-Loop Incident Dossier: Dispatches physical walkdown checklists while strictly inhibiting automated plant trips."
            }
        ])
        st.table(comp_df)

    # =========================================================================
    # TAB 4: ETHICS, SAFETY & RESPONSIBLE DISCLOSURE
    # =========================================================================
    with arch_tabs[3]:
        st.markdown("### ⚖️ Industrial Cybersecurity Ethics & Responsible Engineering Principles")
        
        st.warning(
            """
            #### 1. The Human Safety & Environmental Primacy Principle (IEC 61508)
            In industrial process control, human life, safety, and environmental protection strictly supersede automated IT actions. 
            An automated AI system must NEVER trip an operational chemical reactor or refinery furnace without human engineer validation, 
            as uncontrolled shutdown transients can induce catastrophic thermal overpressure and toxic releases.
            """
        )

        st.markdown(
            """
            #### 2. Strict Academic Non-Targeting Policy:
            - **Exclusively Isolated Environments**: All simulation and VAPT exercises are confined strictly to local memory models, loopback subnets (`192.168.10.0/24`), and public research testbed datasets (HAI 23.05).
            - **Zero External Transmission**: No scan packets, exploits, or probes are ever transmitted to operational industrial facilities, municipal utilities, or external internet hosts.
            - **Data Privacy**: No proprietary facility credentials, internal keys, or raw confidential telemetry are stored in version control.
            
            #### 3. Responsible Vulnerability Disclosure:
            All identified weaknesses in industrial protocols (such as unauthenticated Modbus CWE-306) represent documented public CVEs. In live environments, findings must follow coordinated vulnerability disclosure through CERT/CC or CISA ICS Advisories.
            """
        )
