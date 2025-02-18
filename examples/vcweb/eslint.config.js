import js from "@eslint/js";
import typescript from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import es6Import from "eslint-plugin-import";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks"
import reactRefresh from "eslint-plugin-react-refresh"
import globals from "globals";

export default [
    js.configs.recommended,
    {
        plugins: {
            "@typescript-eslint": typescript,
            import: es6Import,
            react,
            "react-hooks": reactHooks,
            "react-refresh": reactRefresh,
            typescript,
        },
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaFeatures: {
                    jsx: true,
                    modules: true,
                },
                ecmaVersion: "latest",
            },
            globals: {
                JSX: "readonly",
                ...globals.browser,
            },
        },
        files: ["**/*.{js,jsx,ts,tsx}"],
        rules: {
            ...typescript.configs["eslint-recommended"].rules,
            ...typescript.configs["recommended"].rules,
            ...react.configs.recommended.rules,
            ...reactHooks.configs.recommended.rules,
            "react/jsx-uses-react": "error",
            "react/jsx-uses-vars": "error",
            "react/prop-types": 0,
            "react/react-in-jsx-scope": 0,
            "react-refresh/only-export-components": [
                "warn",
                { allowConstantExport: true },
            ],
            camelcase: "error",
            "prefer-const": "error",
            eqeqeq: ["error", "smart"],
            "import/order": [
                "warn",
                {
                    groups: [
                        "builtin",
                        "external",
                        "internal",
                    ],
                    pathGroups: [
                        {
                            pattern: "react",
                            group: "external",
                            position: "before",
                        },
                    ],
                    pathGroupsExcludedImportTypes: [
                        "react"
                    ],
                    "newlines-between": "always",
                    alphabetize: {
                        order: "asc",
                        caseInsensitive: true
                    },
                },
            ],
            "no-restricted-imports": [
                "error",
                {
                    patterns: ["@mui/*/*/*", "!@mui/material/test-utils/*"],
                }
            ],
            "@typescript-eslint/no-unused-vars": [
                "warn", {
                    argsIgnorePattern: "^_",
                    varsIgnorePattern: "^_",
                }
            ]
        },
        settings: {
            react: {
                version: "detect",
            },
        },
    },
    {
        ignores: [".pnpm-store", "pnpm-lock.yaml", "**/node_modules/*", "**/dist/*"],
    },
];
