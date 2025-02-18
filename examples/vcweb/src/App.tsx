import CssBaseline from "@mui/material/CssBaseline";
import { ThemeProvider } from "@mui/material/styles";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import Home from "./Home";
import Layout from "./Layout";
import Offer from "./Offer";
import Request from "./Request";
import { theme } from "./theme";

const App = () => {
    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <BrowserRouter>
                <Routes>
                    <Route element={<Layout />}>
                        <Route index element={<Home />} />
                        <Route path="/issuer" element={<Offer />} />
                        <Route path="/verifier" element={<Request />} />
                    </Route>
                </Routes>
            </BrowserRouter>
        </ThemeProvider>
    )
};

export default App;
