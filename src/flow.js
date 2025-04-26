require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const {
  decryptFlowRequest,
  encryptFlowResponse,
  FlowEndpointException,
  isRequestSignatureValid,
  getNextScreen,
  getPrivateKey,
} = require("./lib");

// Read private key from file
const privateKeyEnv = process.env.PRIVATE_KEY;
const PRIVATE_KEY = getPrivateKey(privateKeyEnv);
const PASSPHRASE = process.env.PASSPHRASE;

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

router.get("/", (req, res) => {
  res.send("Flow endpoint is working!");
});

module.exports = router;
