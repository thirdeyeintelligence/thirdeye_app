
import React, { useState } from "react";

const useCases = {
  netskope: {
    threats: [
      "Initial Access (T1078) via SaaS logins",
      "Exfiltration (T1041) via unsanctioned cloud apps",
      "Command & Control (T1102) through web services"
    ],
    logs: [
      "Web traffic logs (URLs, domains, user identity)",
      "App activity logs (SaaS uploads/downloads)",
      "DLP policy alerts"
    ],
    sentinelRules: [
      "Netskope - DLP Policy Violation",
      "Netskope - Access to risky app by exec",
      "Multiple uploads to unsanctioned app"
    ]
  },
  portal: {
    threats: [
      "Credential Theft (T1078) via brute force",
      "Privilege Escalation through web interface",
      "Account Takeover from exposed login portals"
    ],
    logs: [
      "Web server logs (user agents, IPs, login attempts)",
      "Azure AD sign-in logs",
      "App activity (reset password, MFA usage)"
    ],
    sentinelRules: [
      "Excessive failed logins",
      "Login from multiple countries",
      "Successful login after multiple failures"
    ]
  }
};

export default function LoggingUseCaseAdvisor() {
  const [selectedOption, setSelectedOption] = useState("");

  const renderUseCase = () => {
    const data = useCases[selectedOption];
    if (!data) return null;

    return (
      <div style={{ marginTop: '1rem', padding: '1rem', border: '1px solid #ccc', backgroundColor: '#f9f9f9' }}>
        <h2>🔍 Threat Scenarios (MITRE)</h2>
        <ul>
          {data.threats.map((t, i) => (
            <li key={i}>{t}</li>
          ))}
        </ul>

        <h2>📦 Required Logs</h2>
        <ul>
          {data.logs.map((l, i) => (
            <li key={i}>{l}</li>
          ))}
        </ul>

        <h2>🚨 Sentinel Alert Rules</h2>
        <ul>
          {data.sentinelRules.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </div>
    );
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '700px', margin: '0 auto' }}>
      <h1>🧠 Guided Logging Use Case Advisor</h1>
      <label htmlFor="onboarding">What are you onboarding?</label>
      <select
        id="onboarding"
        onChange={(e) => setSelectedOption(e.target.value)}
        value={selectedOption}
        style={{ display: 'block', margin: '1rem 0', padding: '0.5rem' }}
      >
        <option value="">Select a system or app</option>
        {Object.keys(useCases).map((key) => (
          <option key={key} value={key}>
            {key.charAt(0).toUpperCase() + key.slice(1)}
          </option>
        ))}
      </select>

      {renderUseCase()}
    </div>
  );
}
