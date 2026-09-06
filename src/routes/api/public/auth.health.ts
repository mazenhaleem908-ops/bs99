import { createFileRoute } from "@tanstack/react-router";
import { jsonResponse, preflight } from "@/lib/http";
export const Route=createFileRoute("/api/public/auth/health")({server:{handlers:{OPTIONS:async({request})=>preflight(request),GET:async({request})=>{
  const env={DATABASE_URL:!!process.env['DATABASE_URL'],RESEND_API_KEY:!!process.env['RESEND_API_KEY'],GOOGLE_CLIENT_ID:!!process.env['GOOGLE_CLIENT_ID'],GOOGLE_CLIENT_SECRET:!!process.env['GOOGLE_CLIENT_SECRET'],MOONPAY_SECRET_KEY:!!process.env['MOONPAY_SECRET_KEY']};
  let dbOk=false;try{if(env.DATABASE_URL){const {db}=await import('@/lib/db');await db()`SELECT 1`;dbOk=true}}catch{}
  const ok=env.DATABASE_URL&&env.RESEND_API_KEY&&env.GOOGLE_CLIENT_ID&&env.GOOGLE_CLIENT_SECRET&&env.MOONPAY_SECRET_KEY&&dbOk;
  return jsonResponse(request,{ok,env,database:dbOk},ok?200:503);
}}}});
