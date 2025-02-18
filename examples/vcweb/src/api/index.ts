import { ErrorResponse } from "../types/generated";

export const stdHeaders = {
    "Content-Type": "application/json",
};

export const authHeader = (token: string) => ({
    ...stdHeaders,
    Authorization: `Bearer ${token}`,
});

export const svcUrl = import.meta.env.VITE_VERCRE_HTTP_ADDR || "http://localhost:8080";

// Generic error message for API calls.
export const returnError = (action: string): string => {
    console.error("failed service call", { "action": action });
    return `An error occurred attempting ${action}. Please try again later.`;
};

// A weak type guard for ErrorResponse. Good enough for this example app since
// we know all the other possible types the API can return.
export const instanceOfErrorResponse = (obj: unknown): obj is ErrorResponse => {
    return typeof obj === "object" && obj !== null && "message" in obj;
};
