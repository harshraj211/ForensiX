import { useParams } from "react-router-dom";
import { AiIntelligenceCenter } from "./AiIntelligenceCenter";

export function AiIntelligenceCenterPage() {
  const { caseId = "" } = useParams();

  return (
    <div className="mx-auto max-w-6xl p-4 sm:p-6">
      <AiIntelligenceCenter caseId={caseId} />
    </div>
  );
}
