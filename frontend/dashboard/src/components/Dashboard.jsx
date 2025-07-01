import React, { useEffect, useState } from 'react';
import './dashboard.css';

const Dashboard = () => {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    fetch('http://127.0.0.1:5000/logs')
      .then(response => response.json())
      .then(data => setLogs(data))
      .catch(error => console.error('Error fetching logs:', error));
  }, []);

  return (
    <div className="dashboard-container">
      <h2>📊 Insider Threat Logs</h2>
      <table className="log-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>User ID</th>
            <th>Resource</th>
            <th>Action</th>
            <th>Data Transferred</th>
            <th>Threat</th>
            <th>Download</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, idx) => (
            <tr key={idx}>
              <td>{log.timestamp}</td>
              <td>{log.user_id}</td>
              <td>{log.resource_accessed}</td>
              <td>{log.action}</td>
              <td>{log.data_transferred}</td>
              <td className={log.threat === 'malicious' ? 'malicious' : 'normal'}>
                {log.threat}
              </td>
              <td>
                <button
                  onClick={() =>
                    window.open(
                      `http://127.0.0.1:5000/download/${encodeURIComponent(log.resource_accessed)}?user_id=${log.user_id}`,
                      '_blank'
                    )
                  }
                  className="download-btn"
                >
                  Download
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Dashboard;
