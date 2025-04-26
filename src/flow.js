require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const {
  decryptFlowRequest,
  encryptFlowResponse,
  FlowEndpointException,
  isRequestSignatureValid,
  getNextScreen,
} = require("./lib");
// Read private key from file
const privateKeyEnv = process.env.PRIVATE_KEY;
let PRIVATE_KEY;

// Handle different possible formats
if (privateKeyEnv.includes("-----BEGIN PRIVATE KEY-----")) {
  // If headers are already present, just ensure newlines are correct
  PRIVATE_KEY = privateKeyEnv.replace(/\\n/g, "\n");
} else {
  // If headers are missing or format is incorrect, format it properly
  const keyContent = privateKeyEnv.replace(/[\r\n\s]/g, "");

  // Build properly formatted key
  PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n";
  for (let i = 0; i < keyContent.length; i += 64) {
    PRIVATE_KEY += keyContent.slice(i, i + 64) + "\n";
  }
  PRIVATE_KEY += "-----END PRIVATE KEY-----\n";
}
const PASSPHRASE = process.env.PASSPHRASE;

// Configure body parser to get raw body for signature verification
const router = express.Router();
router.use(
  bodyParser.json({
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf.toString(encoding || "utf8");
    },
  })
);

// Handle POST requests for incoming Flow data
router.post("/", async (req, res) => {
  let decryptedRequest;
  let flowToken;
  let currentScreenId;
  let aesKeyBuffer;
  let initialVectorBuffer;

  try {
    if (!PRIVATE_KEY) {
      throw new Error(
        'Private key is empty. Please check your env variable "PRIVATE_KEY".'
      );
    }

    if (!isRequestSignatureValid(req)) {
      return res.status(432).send();
    }

    decryptedRequest = decryptFlowRequest(req.body, PRIVATE_KEY, PASSPHRASE);

    // Extract the aesKeyBuffer,body and initialVectorBuffer from the decrypted request
    const { aesKeyBuffer, initialVectorBuffer, decryptedBody } =
      decryptedRequest;

    const screenResponse = await getNextScreen(decryptedBody);
    console.log("👉 Response to Encrypt:", screenResponse);

    res.send(
      encryptFlowResponse(screenResponse, aesKeyBuffer, initialVectorBuffer)
    );
  } catch (error) {
    console.error("Error processing webhook event:", error);
    if (err instanceof FlowEndpointException) {
      return res.status(err.statusCode).send();
    }

    // Send a generic error response back to the user within the flow if possible
    if (aesKeyBuffer && initialVectorBuffer && flowToken) {
      try {
        let genericErrorResponseContent = {
          version: "7.0",
          screen: currentScreenId || "ONBOARDING_CONSENT_SCREEN",
          data: {
            error_message:
              "An internal server error occurred. Please try again.",
          },
        };

        const encryptedErrorResponse = encryptFlowResponse(
          genericErrorResponseContent,
          aesKeyBuffer,
          initialVectorBuffer
        );

        return res.status(500).json({
          flow_token: flowToken,
          encrypted_flow_response: encryptedErrorResponse,
        });
      } catch (encryptError) {
        console.error(
          "Failed to encrypt generic error response during main error handling:",
          encryptError
        );

        return res
          .status(500)
          .send("Internal server error (failed to encrypt generic error)");
      }
    } else {
      console.error(
        "Could not encrypt generic error response because AES key/IV/token not available"
      );
      return res.status(500).send("Internal server error");
    }
  }
});

//
// Handle GET requests for testing,return simple text
router.get("/", (req, res) => {
  res.send("Flow endpoint is working!");
});

module.exports = router;
