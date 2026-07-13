import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextRequest, NextResponse } from "next/server";
import {
  clerkEnabled,
  clerkPublishableKey,
  clerkSecretKey,
  productionAuthRequired,
} from "@/lib/auth";

const isPublicRoute = createRouteMatcher(["/", "/security", "/sign-in(.*)", "/sign-up(.*)"]);

export default clerkEnabled
  ? clerkMiddleware(async (auth, req) => {
      if (!isPublicRoute(req)) {
        await auth.protect();
      }
    }, { publishableKey: clerkPublishableKey, secretKey: clerkSecretKey })
  : productionAuthRequired
    ? (request: NextRequest) => isPublicRoute(request)
      ? NextResponse.next()
      : new NextResponse("Authentication is not configured", { status: 503 })
    : () => NextResponse.next();

export const config = {
  matcher: [
    // Skip Next.js internals and static files
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
