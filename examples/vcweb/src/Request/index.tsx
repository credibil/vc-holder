import { useEffect, useState } from "react";

import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Grid from "@mui/material/Grid2";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import { useMutation } from "@tanstack/react-query";
import { useSetRecoilState } from "recoil";

import CreateRequest from "./CreateRequest";
import { instanceOfErrorResponse } from "../api";
import { createRequest } from "../api/verification";
import FullLogo from "../components/FullLogo";
import QrCode from "../components/QrCode";
import { headerState } from "../state";
import {
    GenerateInputDescriptor, GenerateRequest,
    GenerateRequestResponse
} from "../types/generated";

type SupportedCredential = "EmployeeID_JWT" | "Developer_JWT";

const Request = () => {
    const [processing, setProcessing] = useState<SupportedCredential | null>(null);
    const [qrCode, setQrCode] = useState<string>("");
    const setHeader = useSetRecoilState(headerState);

    // Translate some hard-coded values for the supported credentials.
    const purpose = (configId: SupportedCredential): string => {
        switch (configId) {
            case "EmployeeID_JWT":
                return "To verify employment status";
            case "Developer_JWT":
                return "To verify developer competency";
            default:
                return "";
        }
    };

    const inputDescriptors = (configId: SupportedCredential): GenerateInputDescriptor[] => {
        switch (configId) {
            case "EmployeeID_JWT":
                return [{
                    id: "EmployeeID_JWT",
                    constraints: {
                        fields: [{
                            path: ["$.type"],
                            // eslint-disable-next-line camelcase
                            filter_value: "EmployeeIDCredential",
                        }],
                    },
                }];
            case "Developer_JWT":
                return [{
                    id: "Developer_JWT",
                    constraints: {
                        fields: [{
                            path: ["$.type"],
                            // eslint-disable-next-line camelcase
                            filter_value: "DeveloperCredential",
                        }],
                    },
                }];
            default:
                return [];
        }
    };

    useEffect(() => {
        setHeader({
            title: "Credential Verifier",
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

    // API call to create a presentation request.
    const mut = useMutation({
        mutationFn: async (generateRequest: GenerateRequest) => {
            const response = await createRequest(generateRequest);
            if (instanceOfErrorResponse(response)) {
                console.error(response);
            } else {
                const res = response as GenerateRequestResponse;
                setQrCode(res.qr_code);
            }
        },
        onError: (err) => {
            console.error(err);
        },
        retry: false,
    });

    const handleCreateRequest = async (configId: SupportedCredential) => {
        setProcessing(configId);
        const req: GenerateRequest = {
            purpose: purpose(configId),
            // eslint-disable-next-line camelcase
            input_descriptors: inputDescriptors(configId),
        };
        mut.mutate(req);
    };

    const handleReset = () => {
        setProcessing(null);
    };

    return (
        <Stack spacing={4} py={4} id="pageContent">
            <Typography variant="h1">
                Credential Presentation
            </Typography>
            {processing === null &&
                <Typography variant="body1">
                    Start the process of verifying a credential by choosing the credential type you
                    would like to verify. The user can then scan a QR code to present the
                    credential.
                </Typography>
            }
            <Grid container spacing={4}>
                <Grid size={{ xs: 12, sm: 6 }}>
                    {processing === "EmployeeID_JWT"
                        ? <QrCode title="Employee ID" type="verify" image={qrCode} />
                        : <CreateRequest
                            configId="EmployeeID_JWT"
                            onCreate={() => handleCreateRequest("EmployeeID_JWT")}
                        />
                    }
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                    {processing === "Developer_JWT"
                        ? <QrCode title="Developer" type="verify" image={qrCode} />
                        : <CreateRequest
                            configId="Developer_JWT"
                            onCreate={() => handleCreateRequest("Developer_JWT")}
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
        </Stack>
    );
};

export default Request;