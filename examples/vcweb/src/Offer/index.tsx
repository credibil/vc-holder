import { ChangeEvent, useEffect, useState } from "react";

import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Grid from "@mui/material/Grid2";
import Stack from "@mui/material/Stack";
import Switch from "@mui/material/Switch";
import Typography from "@mui/material/Typography";
import { useMutation } from "@tanstack/react-query";
import { useSetRecoilState } from "recoil";

import CreateOffer from "./CreateOffer";
import OfferJson from "./OfferJson";
import { instanceOfErrorResponse } from "../api";
import { createOffer } from "../api/issuance";
import FullLogo from "../components/FullLogo";
import QrCode from "../components/QrCode";
import { headerState } from "../state";
import { CreateOfferRequest, CreateOfferResponse } from "../types/generated";

const Offer = () => {
    const [processing, setProcessing] = useState<"EmployeeID_JWT" | "Developer_JWT" | null>(null);
    const [pin, setPin] = useState<string>("");
    const [qrCode, setQrCode] = useState<string>("");
    const [offerJson, setOfferJson] = useState<string>("");
    const [showJson, setShowJson] = useState(false);
    const setHeader = useSetRecoilState(headerState);

    useEffect(() => {
        setHeader({
            title: "Credential Issuer",
            action: undefined,
            secondaryAction: undefined,
        });
    }, [setHeader]);

    // Effect to scroll back to top on reset
    useEffect(() => {
        if (processing === null) {
            document.getElementById("pageContent")?.scrollTo({
                top: 0,
                behavior: "smooth",
            });
        }
    }, [processing]);

    // API call to create a credential offer
    const mut = useMutation({
        mutationFn: async (createOfferRequest: CreateOfferRequest) => {
            const response = await createOffer(createOfferRequest);
            if (instanceOfErrorResponse(response)) {
                console.error(response);
            } else {
                const res = response as CreateOfferResponse;
                setQrCode(res.qr_code);
                setPin(res.tx_code || "");
                setOfferJson(res.offer_json);
            }
        },
        onError: (err) => {
            console.error(err);
        },
        retry: false,
    });

    const handleCreateOffer = async (configId: "EmployeeID_JWT" | "Developer_JWT") => {
        setProcessing(configId);
        const req: CreateOfferRequest = {
            // eslint-disable-next-line camelcase
            credential_issuer: "http://credibil.io", // Gets ignored by the sample API.
            // eslint-disable-next-line camelcase
            subject_id: "normal_user",
            // eslint-disable-next-line camelcase
            credential_configuration_id: configId,
            // eslint-disable-next-line camelcase
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            // eslint-disable-next-line camelcase
            tx_code_required: configId === "EmployeeID_JWT",
        };
        mut.mutate(req);
    };

    const handleReset = () => {
        setProcessing(null);
        setPin("");
        setShowJson(false);
    };

    return (
        <Stack spacing={4} py={4} id="pageContent">
            <Typography variant="h1">
                Credential Offer
            </Typography>
            {processing === null &&
                <Typography variant="body1">
                    Start the process of issuing a credential by choosing the credential type you would
                    like to issue. The user can then scan a QR code to accept the offer.
                </Typography>
            }
            <Grid container spacing={4}>
                <Grid size={{ xs: 12, sm: 6 }}>
                    {processing === "EmployeeID_JWT"
                        ? <>
                        {
                            showJson
                                ? <OfferJson title="Employee ID" offer={offerJson} pin={pin} />
                                : <QrCode title="Employee ID" type="issue" image={qrCode} pin={pin} />
                        }
                            <QrOrJson checked={showJson} onChange={() => setShowJson(!showJson)} />
                        </>
                        : <CreateOffer
                            configId="EmployeeID_JWT"
                            disabled={processing !== null}
                            onCreate={() => handleCreateOffer("EmployeeID_JWT")}
                        />
                    }
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                    {processing === "Developer_JWT"
                        ? <>
                        {
                            showJson
                                ? <OfferJson title="Developer" offer={offerJson} pin={pin} />
                                : <QrCode title="Developer" type="issue" image={qrCode} pin={pin} />
                        }
                            <QrOrJson checked={showJson} onChange={() => setShowJson(!showJson)} />
                        </>
                        : < CreateOffer
                            configId="Developer_JWT"
                            disabled={processing !== null}
                            onCreate={() => handleCreateOffer("Developer_JWT")}
                        />
                    }
                </Grid>
            </Grid>
            <Box sx={{ display: "flex", justifyContent: "center" }}>
                <Button
                    disabled={processing === null}
                    variant="contained"
                    color="secondary"
                    onClick={handleReset}
                    sx={{ maxWidth: "200px" }}
                >
                    Start Over
                </Button>
            </Box>
            <FullLogo />
        </Stack >
    );
};

const QrOrJson = (props: { checked: boolean, onChange: (event: ChangeEvent<HTMLInputElement>) => void }) => {
    return (
        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <Typography variant="body2">QR Code</Typography>
            <Switch checked={props.checked} onChange={props.onChange} />
            <Typography variant="body2">JSON</Typography>
        </Stack>
    );
}

export default Offer;