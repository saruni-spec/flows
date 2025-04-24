require("dotenv").config();
const express = require("express");

const bodyParser = require("body-parser");
const fs = require("fs");
const {
  decryptFlowRequest,
  encryptFlowResponse,
  flowJson,
  FlowEndpointException,
  isRequestSignatureValid,
  getNextScreen,
} = require("./lib");
// Read private key from file

const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY, "utf8");

const APP_SECRET = process.env.APP_SECRET;

const PASSPHRASE = process.env.PASSPHRASE;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

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
  let rawBody;
  let parsedBody;
  let decryptedRequest;
  let flowToken;
  let currentScreenId;
  let event;
  let decryptedPayload;
  let aesKeyBuffer;
  let initialVectorBuffer;

  try {
    // 1. Read the raw request body for signature verification
    rawBody = req.rawBody;

    // 2. Verify the request signature
    const signatureHeader = req.headers["x-hub-signature-256"];
    if (!isRequestSignatureValid(rawBody, signatureHeader, APP_SECRET)) {
      // Return status code 432 if request signature does not match.
      console.error("Signature validation failed. Returning 432.");
      return res.status(432).end();
    }
    console.log("Signature validation successful.");

    // 3. Parse the raw body string into JSON
    parsedBody = JSON.parse(rawBody);
    let flowData;
    // 4. Determine if it's a standard nested Flow event or the observed top-level structure
    if (parsedBody.entry?.[0]?.changes?.[0]?.value?.flows?.[0]) {
      console.log("Identified standard nested Flow event structure.");
      flowData = parsedBody.entry[0].changes[0].value.flows[0];
      // Standard structure contains all info here
      flowToken = flowData.flow_token;
      currentScreenId = flowData.screen;
      event = flowData.event;
      decryptedPayload = flowData.data || flowData.payload; // Payload might be in 'data' or 'payload' depending on event type
    } else if (
      parsedBody.encrypted_flow_data &&
      parsedBody.encrypted_aes_key &&
      parsedBody.initial_vector
    ) {
      // This matches the structure observed in your logs (top-level crypto fields)
      // In this structure, we only have the crypto fields initially.
      // The screen, event, and actual payload will be inside the decrypted data.
      // We will extract flow_token, screen, event, payload *after* decryption.
      flowData = parsedBody; // Use the top-level body as the source for decryption
      // flowToken, currentScreenId, event, decryptedPayload will be set after decryption
    } else {
      console.log("Received non-flow or malformed webhook event structure.");
      // Not a Flow event or recognized structure
      return res
        .status(200)
        .send(
          "Event received, but not a recognized Flow interaction structure"
        );
    }

    // Decrypt the incoming flow data payload
    decryptedRequest = decryptFlowRequest(flowData, PRIVATE_KEY, PASSPHRASE);

    // Extract the aesKeyBuffer,body and initialVectorBuffer from the decrypted request
    aesKeyBuffer = decryptedRequest.aesKeyBuffer;
    initialVectorBuffer = decryptedRequest.initialVectorBuffer;
    const decryptedBody = decryptedRequest.decryptedBody;

    const screenResponse = await getNextScreen(decryptedBody);
    console.log("👉 Response to Encrypt:", screenResponse);

    res.send(
      encryptFlowResponse(screenResponse, aesKeyBuffer, initialVectorBuffer)
    );
  } catch (error) {
    console.error("Error processing webhook event:", error);

    // Handle specific FlowEndpointExceptions (like decryption/key/format errors)
    if (error instanceof FlowEndpointException) {
      console.error(
        `Flow Endpoint Exception: Status ${error.statusCode}, Message: ${error.message}`
      );
      // For FlowEndpointExceptions, return the specific Meta status code and an *encrypted* error response
      // The error response body should be { error_msg: "..." } and must be encrypted.
      try {
        const errorResponseContent = { error_msg: error.message };
        // Need original AES key/IV from request to encrypt error.
        // This might fail if the error happened *during* key/IV extraction/decryption.
        // If aesKeyBuffer or initialVectorBuffer are not available, fall back to a non-flow error response (e.g., 500).
        if (aesKeyBuffer && initialVectorBuffer && flowToken) {
          const encryptedErrorResponse = encryptFlowResponse(
            errorResponseContent,
            aesKeyBuffer,
            initialVectorBuffer
          );
          return res.status(error.statusCode).json({
            flow_token: flowToken,
            encrypted_flow_response: encryptedErrorResponse,
          }); // Return the specific error status code (400, 421 etc.)
        } else {
          console.error(
            "Could not encrypt FlowEndpointException error response as key/IV/token were not available. Returning 500."
          );
          return res.status(500).send(error.message); // Fallback 500 response
        }
      } catch (encryptError) {
        console.error(
          "Failed to encrypt FlowEndpointException error response:",
          encryptError
        );
        // If encryption of the error response fails, fall back to a generic 500
        return res
          .status(500)
          .send("Internal server error (failed to encrypt flow error)");
      }
    }

    // Handle other unexpected errors (server logic errors etc.)
    console.error("Caught unhandled internal error:", error);

    // Attempt to send a generic error response back to the user within the flow if possible
    let genericErrorResponseContent = {
      version: flowJson.version, // Use flow version
      screen: currentScreenId || "ONBOARDING_CONSENT_SCREEN", // Try current screen, fallback to start
      data: {
        error_message: "An internal server error occurred. Please try again.", // Needs layout support on the screen
        // You might add a button to go back to main menu etc. in a real flow error screen
      },
    };

    // Attempt to encrypt the generic error response using the key/IV from the request if available
    if (aesKeyBuffer && initialVectorBuffer && flowToken) {
      try {
        const encryptedErrorResponse = encryptFlowResponse(
          genericErrorResponseContent,
          aesKeyBuffer,
          initialVectorBuffer
        );
        return res.status(200).json({
          flow_token: flowToken, // Use the token from the failed request
          encrypted_flow_response: encryptedErrorResponse,
        }); // Return 200 OK, but the payload indicates an error screen
      } catch (encryptError) {
        console.error(
          "Failed to encrypt generic error response during main error handling:",
          encryptError
        );
        // If encryption of the error response fails, fall back to a generic 500
        return res
          .status(500)
          .send("Internal server error (failed to encrypt generic error)");
      }
    } else {
      // If we don't have the key/IV/token (e.g., error happened before or during decryption), just return 500
      console.error(
        "Could not encrypt generic error response because AES key/IV/token not available. Returning 500."
      );
      return res.status(500).send("Internal server error");
    }
  }
});

module.exports = router;
