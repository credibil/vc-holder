import { JSX } from "react";

import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";

import Logo from "./Logo";

export type HeaderProps = {
    action?: JSX.Element;
    secondaryAction?: JSX.Element;
    title?: string;
};

const Header = (props: HeaderProps) => {
    const { action, secondaryAction, title } = props;

    return (
        <AppBar
            elevation={0}
            color="secondary"
            position="fixed"
        >
            <Toolbar>
                {action || <Logo />}
                <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="h4" sx={{ px: 3 }}>{title}</Typography>
                </Box>
                {secondaryAction}
            </Toolbar>
        </AppBar>
    );
};

export default Header;
