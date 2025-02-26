export const components = {
    MuiButton: {
        styleOverrides: {
            contained: {
                padding: "16px 16px",
                borderRadius: "4px",
                boxShadow: "none",
            },
            containedSecondary: {
                color: "#4D6BFF",
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
