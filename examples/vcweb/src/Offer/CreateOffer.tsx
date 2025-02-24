import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

export type CreateOfferProps = {
    configId: "EmployeeID_JWT" | "Developer_JWT";
    disabled?: boolean;
    onCreate: () => void;
};

const CreateOffer = (props: CreateOfferProps) => {
    const { configId, disabled, onCreate } = props;

    const title = () => {
        switch (configId) {
            case "EmployeeID_JWT":
                return "Employee ID";
            case "Developer_JWT":
                return "Developer";
        }
    };

    const discription = () => {
        switch (configId) {
            case "EmployeeID_JWT":
                return "A credential that asserts the holder is an employee of the issuer organization";
            case "Developer_JWT":
                return "A credential that asserts the holder has a certain level of proficiency in software development";
        }
    };

    return (
        <Box
            sx={{
                borderRadius: "8px",
                p: 6,
                backgroundColor: theme => theme.palette.background.paper,
            }}
        >
            <Stack spacing={2}>
                <Typography variant="h5" sx={{ color: theme => disabled ? theme.palette.action.disabled : "inherit" }}>
                    {title()}
                </Typography>
                <Typography variant="body2" sx={{ color: theme => disabled ? theme.palette.action.disabled : "inherit" }}>
                    {discription()}
                </Typography>
                <Box sx={{
                    display: "flex", justifyContent: "center"
                }}>
                    < Button
                        disabled={disabled}
                        variant="contained"
                        color="primary"
                        onClick={onCreate}
                        sx={{
                            maxWidth: "200px"
                        }}
                    >
                        Create Offer
                    </Button>
                </Box>
            </Stack >
        </Box >
    );
};

export default CreateOffer;