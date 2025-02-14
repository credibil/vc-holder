import { atom } from "recoil";

import { HeaderProps } from "./Layout/Header";

export const headerState = atom<HeaderProps>({
    key: "header",
    default: {
        title: undefined,
        action: undefined,
        secondaryAction: undefined,
    },
});
