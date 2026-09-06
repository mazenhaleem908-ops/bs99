import { createFileRoute } from "@tanstack/react-router";
export const Route=createFileRoute("/auth/google/start")({server:{handlers:{GET:async({request})=>{const u=new URL(request.url);const ret=u.searchParams.get("return")||"/";return new Response(null,{status:302,headers:{location:`/api/public/auth/google/start?return=${encodeURIComponent(ret)}`,"cache-control":"no-store"}});}}}});
