# Sharing Guide: Qualys-ME Integration

---
#### **Customer Setup & Automation Instructions**

**Step 1: Environment Setup**
1.  **Extract** the Zip file to your desired folder.
2.  **Open PowerShell** as Administrator and navigate to the extracted folder.
3.  **Run the Setup Script**:
    ```powershell
    .\scripts\Slave\setup_env.ps1
    ```
    *This will automatically create a fresh environment and install the latest versions of all required libraries.*

**Step 2: Configuration**
*   Update `Config\.env` with your Qualys and ServiceDesk Plus credentials.

**Step 3: Permanent Automation (Windows Task Scheduler)**
1.  Open `Config\.env`.
2.  Set your desired schedule in the **Automation Settings** section (Frequency, Time, Day).
3.  Run the automation script:
    ```powershell
    .\scripts\Slave\automate_task.ps1
    ```
**Step 4: Technician Assignment (Optional)**
1.  In `Config\.env`, locate the **Technician Assignment Settings**.
2.  Set **`SDP_ASSIGNMENT_MODE`** to `RoundRobin` (Even rotation) or `Random`.
3.  Add your technician names or emails to **`SDP_TECHNICIAN_LIST`** (comma-separated).
    *   *Example: "Brammadevan K, support@rsctec.com"*

---


