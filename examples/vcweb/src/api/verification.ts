import { stdHeaders, svcUrl } from "./index";
import { ErrorResponse, GenerateRequest, GenerateRequestResponse } from "../types/generated";

// Create a credential request.
export const createRequest = async (req: GenerateRequest)
    : Promise<GenerateRequestResponse | ErrorResponse> => {

    const url = `${svcUrl}/create_request`;
    const response = await fetch(url, {
        method: "POST",
        headers: { ...stdHeaders },
        body: JSON.stringify(req),
    });
    const result = await response.json();
    return result;
};
