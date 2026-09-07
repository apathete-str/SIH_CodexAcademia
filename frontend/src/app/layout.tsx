import './globals.css';

export const metadata = { title: 'Sentinel | Email Threat Intelligence', description: 'AI-powered email threat detection and forensic intelligence' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
