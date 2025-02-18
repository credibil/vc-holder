export const components = {
    MuiButton: {
        styleOverrides: {
            contained: {
                borderRadius: "4px",
                boxShadow: "none",
            },
            containedSecondary: {
                color: "#ffffff",
            },
            outlined: {
                borderRadius: "4px",
            },
            root: {
                "&:hover": {
                    boxShadow: "none",
                },
            },
        },
    },
};
