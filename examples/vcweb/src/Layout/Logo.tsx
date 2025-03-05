import Box from "@mui/material/Box";
import { useNavigate } from "react-router-dom";

import logo from "./logo.svg";
import logoInverse from "./LogoInverse.svg";
import { useAppBarHeight } from "./useAppBarHeight";

export type LogoProps = {
    inverse?: boolean;
};

const Logo = (props: LogoProps) => {
    const appBarHeight = useAppBarHeight();
    const navigate = useNavigate();

    return (
        <Box
            component="img"
            src={props.inverse ? logoInverse : logo}
            alt="Credibil Verifiable Credentials"
            sx={{
                cursor: "pointer", height: `calc(0.8 * ${appBarHeight}px)`
            }}
            onClick={() => navigate("/")}
        />
    );
};

export default Logo;
