import Box from "@mui/material/Box";

import logo from "./fulllogo.svg";

const FullLogo = () => {
    return (
        <Box
            p={4}
            sx={{
                alignItems: "center",
                backgroundColor: theme => theme.palette.secondary.main,
                borderRadius: "8px",
                display: "flex",
                height: "100%",
                justifyContent: "center",
            }}
        >
            <Box
                component="img"
                src={logo}
                alt="Vercre Veriable Credentials"
                sx={{
                    width: 300,
                }}
            />
        </Box>
    );
};

export default FullLogo;