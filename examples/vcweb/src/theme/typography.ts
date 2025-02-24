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

export const typography = {
    fontFamily: "GT-Ultra-Standard-Light",
    h1: {
        fontFamily: "GT-Ultra-Median-Light",
        fontSize: "3.5rem",
        lineHeight: 1.167,
        letterSpacing: "-0.0625rem",
    },
    h2: {
        fontFamily: "GT-Ultra-Median-Light",
        fontSize: "3.125rem",
        lineHeight: 1.526,
        letterSpacing: "-0.0625rem",
    },
    h3: {
        fontFamily: "GT-Ultra-Median-Light",
        fontSize: "2.5rem",
        lineHeight: 1.375,
    },
    h4: {
        fontFamily: "GT-Ultra-Median-Light",
        fontSize: "1.625rem",
        lineHeight: 1.125,
    },
    h5: {
        fontFamily: "GT-Ultra-Median-Light",
        fontWeight: 700,
        fontSize: "1.25rem",
        lineHeight: 1.375,
    },
    h6: {
        fontFamily: "GT-Ultra-Median-Light",
        fontSize: "1.125rem",
        lineHeight: 1.375,
    },
    subtitle1: {
        fontSize: "1rem",
        lineHeight: 1.375,
    },
    subtitle2: {
        fontSize: "0.875rem",
        lineHeight: 1.375,
    },
    body1: {
        fontSize: "1.125rem",
        lineHeight: 1.4,
    },
    body2: {
        fontSize: "1.125rem",
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
    },
    fineprint: {
        fontSize: "0.75rem",
    },
};
