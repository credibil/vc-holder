import { useEffect } from "react";

import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Grid from "@mui/material/Grid2";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import { useNavigate } from "react-router-dom";
import { useSetRecoilState } from "recoil";

import FullLogo from "../components/FullLogo";
import { headerState } from "../state";

const Home = () => {
    const setHeader = useSetRecoilState(headerState);
    const navigate = useNavigate();

    useEffect(() => {
        setHeader({
            title: "Issuer & Verifier",
            action: undefined,
            secondaryAction: undefined,
        });
    }, [setHeader]);

    return (
        <Stack spacing={4} py={4} id="pageContent">
            <Typography variant="h1">
                Vercre Wallet Demonstrator
            </Typography>
            <Typography variant="body1">
                This simulated web application aids in the demonstration of the sample Vercre
                Wallet.
            </Typography>
            <Grid container spacing={4}>
                <Grid size={{ xs: 12, sm: 6 }}>
                    <Box
                        sx={{
                            border: "solid 1px",
                            borderRadius: "8px",
                            borderColor: theme => theme.palette.primary.light,
                            p: 2,
                        }}
                    >
                        <Typography variant="h5" gutterBottom>
                            Issuer
                        </Typography>
                        <Typography variant="body2">
                            Choose this application to show how the wallet can receive a
                            credential offer from an issuer.
                        </Typography>
                        <Box sx={{ display: "flex", justifyContent: "center", mb: 1, mt: 3 }}>
                            <Button
                                variant="contained"
                                color="primary"
                                onClick={() => navigate("/issuer")}
                                sx={{ maxWidth: "200px" }}
                            >
                                Issue
                            </Button>
                        </Box>
                    </Box>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                    <Box
                        sx={{
                            border: "solid 1px",
                            borderRadius: "8px",
                            borderColor: theme => theme.palette.primary.light,
                            p: 2,
                        }}
                    >
                        <Typography variant="h5" gutterBottom>
                            Verifier
                        </Typography>
                        <Typography variant="body2">
                            Choose this application to show how the wallet can present a verifiable
                            credential to a verifier.
                        </Typography>
                        <Box sx={{
                            display: "flex", justifyContent: "center", mb: 1, mt: 3
                        }}>
                            < Button
                                variant="contained"
                                color="primary"
                                onClick={() => navigate("/verifier")}
                                sx={{ maxWidth: "200px" }}
                            >
                                Verify
                            </Button>
                        </Box>
                    </Box>
                </Grid>
            </Grid >
            <FullLogo />
        </Stack >
    );
};

export default Home;