import Box from "@mui/material/Box";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

export type RequestUrlProps = {
    title?: string;
    url: string;
};

const RequestUrl = (props: RequestUrlProps) => {
    const { title, url } = props;

    return (
        <Box
            sx={{
                borderRadius: "8px",
                p: 6,
                backgroundColor: theme => theme.palette.background.paper,
            }}
        >
            <Stack>
                {title && <Typography variant="h5" gutterBottom>{title}</Typography>}
                <Typography variant="body2" gutterBottom>
                    Copy the presentation request content into your wallet app.
                </Typography>
                <Box sx={{
                    display: "flex", justifyContent: "center"
                }}>
                    < Box
                        component="div"
                        sx={{
                            fontSize: "0.8rem",
                            overflow: "wrap",
                            overflowWrap: "break-word",
                            wordWrap: "break-word",
                            paddingY: 2,
                        }}
                    >
                        <Box component="code">
                            {url}
                        </Box>
                    </Box>
                </Box>
            </Stack >
        </Box >
    );
};

export default RequestUrl;
