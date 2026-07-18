import { ScanProgressClient } from "@/components/scan-progress-client";

export default async function ScanPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  return <ScanProgressClient scanId={scanId} />;
}
