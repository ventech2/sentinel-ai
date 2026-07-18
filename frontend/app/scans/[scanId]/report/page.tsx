import { ReportClient } from "@/components/report-client";

export default async function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  return <ReportClient scanId={scanId} />;
}
