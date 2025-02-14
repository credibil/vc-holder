import Box from "@mui/material/Box";
import { useNavigate } from "react-router-dom";

import logo from "./logo.svg";
import { useAppBarHeight } from "./useAppBarHeight";

const Logo = () => {
    const appBarHeight = useAppBarHeight();
    const navigate = useNavigate();

    return (
        <Box
            component="img"
            src={logo}
            alt="Vercre Veriable Credentials"
            sx={{
                cursor: "pointer", height: `calc(0.8 * ${appBarHeight}px)`
            }}
            onClick={() => navigate("/")}
        />
    );
};

export default Logo;
