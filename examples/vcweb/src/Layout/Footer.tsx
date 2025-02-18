import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Link from "@mui/material/Link";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";

const LINK = "https://vercre.io";
const LINK_TEXT = "Vercre";

const Footer = () => {
    return (
        <AppBar
            elevation={0}
            color="secondary"
            component="footer"
            position="fixed"
            sx={{
                top: "auto", bottom: 0
            }}
        >
            <Toolbar>
                <Box sx={{ flexGrow: 1 }} />
                <Typography variant="fineprint" sx={{ px: 3 }}>
                    <Link
                        color="inherit"
                        href={LINK}
                        rel="noopener"
                        target="_blank"
                        underline="hover"
                    >
                        {LINK_TEXT}
                    </Link>
                </Typography>
            </Toolbar>
        </AppBar >
    );
};

export default Footer;