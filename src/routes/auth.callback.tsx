import { createFileRoute } from "@tanstack/react-router";
export const Route=createFileRoute("/auth/callback")({server:{handlers:{GET:async()=>new Response(null,{status:302,headers:{location:"/"}})}}});
