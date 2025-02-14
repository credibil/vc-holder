import { CSSProperties } from "react";

declare module "@mui/material/styles" {
    interface TypographyVariants {
        fineprint: CSSProperties;
    }
    // This allows configuration using "createTheme"
    interface TypographyVariantsOptions {
        fineprint?: CSSProperties;
    }
}

declare module "@mui/material/Typography" {
    interface TypographyPropsVariantOverrides {
        fineprint: true,
    }
}

const systemFont = [
    "Inter",
    "sans-serif",
].join(",");

export const typography = {
    fontFamily: systemFont,
    h1: {
        fontSize: "2rem",
        fontWeight: 700,
        lineHeight: 1.167,
        letterSpacing: "-0.0625rem",
    },
    h2: {
        fontSize: "3.125rem",
        fontWeight: 400,
        lineHeight: 1.526,
        letterSpacing: "-0.0625rem",
    },
    h3: {
        fontSize: "2.5rem",
        fontWeight: 500,
        lineHeight: 1.375,
    },
    h4: {
        fontSize: "1.625rem",
        fontWeight: 400,
        lineHeight: 1.125,
    },
    h5: {
        fontSize: "1.25rem",
        fontWeight: 700,
        lineHeight: 1.375,
    },
    h6: {
        fontSize: "1.125rem",
        fontWeight: 500,
        lineHeight: 1.375,
    },
    subtitle1: {
        fontSize: "1rem",
        fontWeight: 700,
        lineHeight: 1.375,
    },
    subtitle2: {
        fontSize: "0.875rem",
        fontWeight: 500,
        lineHeight: 1.375,
    },
    body1: {
        fontSize: "1.125rem",
        fontWeight: 400,
        lineHeight: 1.4,
    },
    body2: {
        fontSize: "1.125rem",
        fontWeight: 300,
        lineHeight: 1.11,
    },
    button: {
        fontSize: "1rem",
        lineHeight: 1.125,
        // eslint-disable-next-line @typescript-eslint/prefer-as-const
        textTransform: "uppercase" as "uppercase",
    },
    caption: {
        fontSize: "0.825rem",
        fontWeight: 300,
    },
    fineprint: {
        fontSize: "0.75rem",
        fontWeight: 200,
    },
};
