// report-issue — files GitHub issues sent by the in-app reporter
// (PortfolioFeedback Swift package). Copy to supabase/functions/report-issue/
// in the stack that hosts it; one deployment serves every app in ISSUE_APPS.
//
// Env (function secrets):
//   ISSUE_APPS                 {"otta":{"repo":"Cliefden/Otta","bundleIds":["com.crawik.otta"]}, ...}
//   GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_INSTALLATION_ID   (or GITHUB_TOKEN)
//   ISSUE_ATTACHMENTS_BUCKET   optional, e.g. "issue-attachments" (private bucket; signed URLs)
//
// The app sends the stack's anon key as `apikey` / `Authorization: Bearer`, so
// Kong and the edge runtime's JWT check pass with the default `verify_jwt`.
import { handle } from "../_shared/portfolio/http.ts";
import { reportIssue } from "../_shared/portfolio/github.ts";

Deno.serve(handle((req) => reportIssue(req), { methods: ["POST"], label: "report_issue" }));
