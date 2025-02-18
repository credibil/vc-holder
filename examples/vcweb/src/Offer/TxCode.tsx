import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

export type TxCodeProps = {
    pin: string;
};

const TxCode = (props: TxCodeProps) => {
    const { pin } = props;

    return (
        <Stack mt={4}>
            <Typography variant="h5" gutterBottom>
                Transaction Code (PIN)
            </Typography>
            <Typography variant="body2" gutterBottom>
                To complete the transaction, provide this code when prompted by the wallet.
            </Typography>
            <Box sx={{
                display: "flex", justifyContent: "center"
            }}>
                < Typography variant="h5" gutterBottom>
                    {pin}
                </Typography>
            </Box >
            <Typography variant="fineprint">
                In a real-world scenario, the transaction code would be securely transmitted to
                the user on another channel, not displayed here.
            </Typography>
        </Stack >
    );
};

export default TxCode;
