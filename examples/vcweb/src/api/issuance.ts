import { stdHeaders, svcUrl } from "./index";
import {
    CreateOfferRequest,
    CreateOfferResponse,
    ErrorResponse,
} from "../types/generated";

// Create a credential offer.
export const createOffer = async (req: CreateOfferRequest)
    : Promise<CreateOfferResponse | ErrorResponse> => {

    const url = `${svcUrl}/create_offer`;
    const response = await fetch(url, {
        method: "POST",
        headers: { ...stdHeaders },
        body: JSON.stringify(req),
    });
    const result = await response.json();
    return result;
};
