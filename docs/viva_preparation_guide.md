# Viva Voce Technical Defense Guide: AI-Assisted ICS Cybersecurity

**Student Role**: Student 2 (AI/ML Detection Specialist & Group Leader)  
**Degree / Semester**: 5th-Semester Cybersecurity Project, Manipal University Jaipur  
**Project**: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery  

---

## 1. Quick Technical Reference Card

| Architectural Dimension | Project Implementation Detail | Viva Explanation Key Point |
| :--- | :--- | :--- |
| **Dataset Utilized** | HAI 23.05 (Hardware-in-the-Loop Augmented ICS) | 86 continuous physical process features at 1.0 Hz; 572,400 training samples (~159 hrs); 284,400 test samples (~79 hrs). |
| **Primary Model** | **Isolation Forest** (Unsupervised Behavioral) | Trained *exclusively* on normal operations; isolates anomalies by recursive random partitioning; requires zero attack labels. |
| **Secondary Model** | **Random Forest** (Supervised Ensemble) | 100 decision trees with balanced class weighting; provides high-confidence signature matching and feature attribution. |
| **Baseline Model** | **Logistic Regression** (Supervised Linear) | Transparent linear benchmark; demonstrates that linear boundaries produce excessive false positives (40.38% FPR) in non-linear ICS dynamics. |
| **Data Leakage Defense** | Chronological Splitting + Strict Normal Fitting | Scaler fitted *only* on normal baseline telemetry; test sets transformed using training statistics; target labels isolated. |
| **Zero-Variance Defense** | Scale Denominator Safeguard ($\sigma=0 \to 1.0$) | 20 physical features have zero variance in normal steady-state; standard scaling without defense causes division-by-zero ($\mathrm{NaN}$). |
| **Safety Mandate** | Human-in-the-Loop Advisory (Automated Trips Inactive) | Automated shutdown can cause catastrophic pressure surges and cost \$20k–\$100k/hr in refinery downtime. |

---

## 2. Top 10 Technical Viva Questions & High-Scoring Answers

### Q1: Why did you choose the HAI 23.05 dataset, and does it represent an actual oil refinery?
**Examiner Intent**: Testing whether you understand the dataset's origin or are falsely claiming it is a real oil refinery.  
**High-Scoring Answer**:
> *"No, HAI 23.05 does not represent an actual commercial petroleum refinery. It is a Hardware-in-the-Loop (HIL) industrial control system testbed developed by KISA and research institutes for ICS cybersecurity benchmarking. We utilize it because real refineries cannot be subjected to live cyber attacks or public data release due to safety and national security regulations.  
> However, refinery relevance is established through physical process equivalency: the testbed contains 4 physical process loops—water treatment, boiler steam regulation, heat exchangers, and turbine pump drives—which are the core thermodynamic unit operations of a refinery. Furthermore, we establish end-to-end refinery relevance through our simulated refinery network architecture and controlled attack injection workflow."*

---

### Q2: Why is Accuracy an inappropriate metric for evaluating industrial anomaly detection?
**Examiner Intent**: Testing understanding of class imbalance.  
**High-Scoring Answer**:
> *"In our held-out test dataset of 284,400 observations, attack samples represent only 4.00% (11,384 samples) compared to 96.00% normal samples (273,016 samples). This is a severe 24:1 class imbalance, typical of real SCADA networks where attacks are rare events.  
> If an AI model simply predicts 'Normal (0)' for every single observation, it mathematically achieves a **96.00% Accuracy**, yet its Recall on cyber attacks is **0%**—meaning it completely fails to detect 100% of cyber attacks!  
> Therefore, we evaluate our system using **Precision, Recall, F1-Score, False Positive Rate (FPR), False Negative Rate (FNR), and ROC-AUC**, never Accuracy alone."*

---

### Q3: How did you prevent Data Leakage during the preprocessing and training phases?
**Examiner Intent**: Testing machine learning rigor and methodology.  
**High-Scoring Answer**:
> *"We implemented four strict architectural safeguards against data leakage:  
> 1. **Zero Preprocessing Leakage**: The `StandardScaler` was fitted exclusively on the 572,400 observations of normal baseline operation (`hai-train1` and `hai-train2`). The test scenarios (`hai-test1` and `hai-test2`) were transformed strictly using the baseline $(\mu, \sigma)$ calculated during training.  
> 2. **Target Isolation**: Ground-truth attack labels were completely isolated from the feature matrix $\mathbf{X}$ and never passed into feature scalers.  
> 3. **Chronological / Scenario Splitting**: We strictly prohibited random shuffling (such as `train_test_split(shuffle=True)`). In 1.0 Hz industrial time-series, adjacent observations are autocorrelated; random shuffling leaks future time points into the training set. Instead, we evaluated on chronological, scenario-based test datasets.  
> 4. **No Feature-Time Ingress**: The timestamp column was preserved purely as a metadata reference and excluded from the 86 numerical feature columns."*

---

### Q4: Why did you choose Isolation Forest as your primary production anomaly detector rather than a supervised deep neural network?
**Examiner Intent**: Testing machine learning algorithm selection criteria.  
**High-Scoring Answer**:
> *"In an operational critical infrastructure environment, attacks like **Stuxnet** or **Triton** exploit novel zero-day vulnerabilities. Supervised models require historical labeled attack samples. In Phase 4, we proved that when a supervised Random Forest is trained on Scenario 1, its recall collapses to 1.2% on Scenario 2 because the attacker targeted different physical valves that the model had never seen labeled as malicious.  
> In contrast, **Isolation Forest** is unsupervised: it trains exclusively on normal plant telemetry (572,400 benign samples) to learn the legitimate multi-dimensional physical manifold. It detects outliers by measuring how few random hyper-plane partitions are needed to isolate an observation. Because anomalous physical states deviate from normal correlation across any of the 86 sensor dimensions, Isolation Forest requires zero attack labels during training, making it vastly superior for zero-day threat detection. Furthermore, its inference latency is only 13.85 milliseconds per 1,000 samples, easily satisfying real-time 1.0 Hz SCADA polling requirements."*

---

### Q5: What are zero-variance features in SCADA, and what would happen if your pipeline didn't handle them?
**Examiner Intent**: Testing data engineering and industrial domain awareness.  
**High-Scoring Answer**:
> *"In industrial process plants, certain actuators and safety switches remain static during steady-state normal operations. In our Phase 2 audit, we discovered that 20 features (such as emergency trip switches `P2_Emerg`, `P2_TripEx`, backup pumps `P1_PP01BD`, and alarm thresholds `P1_PIT01_HH`) had a standard deviation of $\sigma = 0$.  
> Standard scaling normalizes data via $z = \frac{x - \mu}{\sigma}$. If $\sigma = 0$, this operation results in **division by zero**, producing `NaN` or `inf` values across the entire dataset. In our Phase 3 pipeline, we implemented a denominator safeguard where any zero scale is replaced with $1.0$, mapping constant normal readings cleanly to $0.0$ and guaranteeing zero `NaNs` across all 856,800 observations."*

---

### Q6: What are the real-world operational consequences of False Positives versus False Negatives in a refinery?
**Examiner Intent**: Testing understanding of the operational technology (OT) reality versus IT security.  
**High-Scoring Answer**:
> *"In industrial control, both error types carry severe real-world consequences:  
> - **False Positives (FPR)**: Every false alarm triggers a control room annunciator. If the FPR is high (like Logistic Regression at 40.38%), operators suffer from **alarm fatigue** and inevitably silence or ignore alarms. Furthermore, if an automated system executes an unverified emergency shutdown (ESD), purging and safely restarting fractional distillation columns costs a refinery **\$20,000 to \$100,000 per hour** in lost production and flaring penalties.  
> - **False Negatives (FNR)**: A false negative occurs when malicious setpoint tampering goes undetected. As shown in Stuxnet, undetected actuator manipulation can cause overpressure explosions, catalytic cracker thermal runaways, or catastrophic turbine destruction.  
> - **Our Design Solution**: Isolation Forest maintains a controlled **3.92% FPR**. Furthermore, while individual point-level recall is 17.56%, **100% of the 52 attack episodes had multiple observations flagged**, ensuring that every attack scenario triggered a security alert before physical damage could culminate."*

---

### Q7: Why can't you feed raw network packets directly into the AI model trained on HAI sensor columns?
**Examiner Intent**: Testing cross-domain data representation understanding (Section 11).  
**High-Scoring Answer**:
> *"Because they represent fundamentally different mathematical feature spaces:  
> - HAI telemetry represents **continuous physical process dynamics** (temperatures in °C, pressures in kPa, valve openings 0–100%).  
> - Network traffic represents **discrete cyber protocols** (source/destination IP, TCP sequence numbers, Modbus function codes).  
> Attempting to feed network packets directly into an 86-column process model would be scientifically invalid. In our Phase 9 integration adapter, we enforced **Cross-Domain Correlation**: the network event (e.g., unauthorized Modbus Function 06 write) and physical telemetry anomaly (e.g., valve demand spike) are evaluated by separate specialized engines and synthesized at the integration layer to confirm a **Coordinated Cyber-Physical Attack**."*

---

### Q8: How did Stuxnet deceive SCADA operators, and how does your project detect similar attacks?
**Examiner Intent**: Testing the Stuxnet case study (Section 14).  
**High-Scoring Answer**:
> *"Stuxnet compromised Siemens S7-300 PLCs driving centrifuge frequency converters. While periodically forcing rotor speeds to destructive resonant frequencies (1,410 Hz to 2 Hz to 1,064 Hz), Stuxnet executed a **Man-in-the-Middle (MitM) sensor replay attack**: it recorded ~21 seconds of normal telemetry and continuously replayed it back to the SCADA HMI. Operators saw normal pressure and temperature readings while centrifuges tore themselves apart.  
> Our project defends against this through **multivariate physical correlation**: when an adversary forces valve demand (`P1_PCV01D`) while attempting to spoof pressure readings (`P1_PIT01`), the joint physical covariance across all 86 sensors breaks down. Our Isolation Forest and Random Forest models evaluate the entire multi-sensor correlation manifold simultaneously, detecting the anomaly even if individual manipulated values appear plausible in isolation."*

---

### Q9: Why does your prototype explicitly inhibit automated emergency plant shutdowns?
**Examiner Intent**: Testing safety standards compliance (ANSI/ISA-62443).  
**High-Scoring Answer**:
> *"In safety-critical industrial automation, executing an automated physical trip based solely on an AI model prediction introduces a dangerous new attack surface: an adversary could craft subtle sensor noise specifically to trick the AI into repeatedly triggering emergency shutdowns, paralyzing refinery operations.  
> Furthermore, sudden physical valve closures can induce severe hydraulic water hammer and catastrophic pipe rupture. In compliance with **ANSI/ISA-62443** and the principle of **Human-in-the-Loop**, our system generates prioritized security alert dossiers and operator checklists, requiring an authorized human engineer to verify field conditions before executing corrective response actions."*

---

### Q10: Walk me through the 8 stages of your end-to-end integration demonstration.
**Examiner Intent**: Verifying the complete project lifecycle demonstration.  
**High-Scoring Answer**:
> *"Our project integrates the work of all three students across an 8-stage lifecycle executed in `simulation/end_to_end_demo.py`:  
> 1. **Simulated Environment**: Student 1's VAPT audit identifies unauthenticated Modbus/TCP on PLC-01 (`VAPT-2026-001`).  
> 2. **Normal Activity**: Plant operates at nominal steady-state (`P1_PCV01D = 28.0%`); AI predicts `NORMAL`.  
> 3. **Controlled Attack Simulation**: Student 3's simulator transmits an unauthorized Modbus Function 06 write from rogue host `192.168.10.99` overriding the valve setpoint to 88%.  
> 4. **Data Collection**: SCADA historian buffers the resulting physical telemetry perturbation.  
> 5. **AI Detection**: Student 2's dual-paradigm engine flags a $24.31\sigma$ physical deviation; threat level elevates to `CRITICAL: COORDINATED CYBER-PHYSICAL ATTACK`.  
> 6. **Security Alert**: Emits alert `ALT-20261019-FB09DF` to the HMI with sensor attribution and non-disruptive remediation guidance.  
> 7. **Mitigation**: An OT firewall rule is deployed dropping the rogue IP, and the operator restores the nominal setpoint.  
> 8. **Re-Testing**: Re-testing confirms that replayed exploit packets are dropped, telemetry normalizes, and finding `VAPT-2026-001` is marked `VERIFIED MITIGATED`."*
