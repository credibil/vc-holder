import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import TxCode from "../Offer/TxCode";

export type OfferJsonProps = {
    title?: string;
    offer: string;
    pin?: string;
};

const OfferJson = (props: OfferJsonProps) => {
    const { title, offer, pin } = props;

    const data = JSON.parse(offer);

    return (
        <Box
            sx={{
                borderRadius: "8px",
                p: 6,
                backgroundColor: theme => theme.palette.background.paper,
            }}
        >
            <Stack>
                {title && <Typography variant="h5" gutterBottom>{title}</Typography>}
                <Typography variant="body2" gutterBottom>
                    Copy the offer content into your wallet app.
                </Typography>
                <Box sx={{
                    display: "flex", justifyContent: "center"
                }}>
                    < Box
                        component="pre"
                        sx={{
                            fontSize: "0.8rem",
                            overflow: "scroll",
                        }}
                    >
                        <Box component="code">
                            {JSON.stringify(data, null, 2)}
                        </Box>
                    </Box>
                </Box>
                {pin && <TxCode pin={pin} />}
            </Stack >
        </Box >
    );
};

export default OfferJson;
