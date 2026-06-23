import axios from 'axios';

const client = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

export const postScan   = (target)  => client.post('/scan', { target });
export const getStatus  = (scanId)  => client.get(`/scan/${scanId}/status`);
export const getResults = (scanId)  => client.get(`/scan/${scanId}/results`);
export const getScans   = ()        => client.get('/scans');
export const getAnalysis = (scanId) => client.get(`/scan/${scanId}/analysis`);

export default client;
