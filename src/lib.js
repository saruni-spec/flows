// app/api/whatsapp-flow/route.js
const crypto = require("crypto");

// const META_PUBLIC_KEY = process.env.META_PUBLIC_KEY; // Not needed for encrypting responses in this flow scheme

// --- Crypto Utility Functions based on Meta's examples ---

/**
 * Decrypts the incoming WhatsApp Flow request body.
 * @param {object} body The part of the request body containing the encrypted fields (encrypted_aes_key, encrypted_flow_data, initial_vector).
 * @param {string} privatePem Your server's private key in PEM format.
 * @param {string} passphrase Passphrase for the private key (if encrypted).
 * @returns {{decryptedBody: object, aesKeyBuffer: Buffer, initialVectorBuffer: Buffer}} Decrypted flow data, AES key buffer, and IV buffer.
 * @throws {FlowEndpointException} If decryption fails with a specific flow error status code.
 */
const decryptFlowRequest = (body, privatePem, passphrase) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
    console.error(
      "Missing required encrypted fields in request body for decryption."
    );
    // Throw a FlowEndpointException with 400 status for bad format
    throw new FlowEndpointException(
      400,
      "Invalid encrypted flow data format: missing fields."
    );
  }

  let privateKey;
  try {
    privateKey = crypto.createPrivateKey({ key: privatePem, passphrase });
  } catch (error) {
    console.error("Failed to load private key:", error);
    // This indicates a server configuration issue, not a client data issue
    throw new Error("Server private key configuration error."); // Throw regular Error for 500 status
  }

  let decryptedAesKey = null;
  try {
    // decrypt AES key created by client using your private RSA key
    decryptedAesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );
  } catch (error) {
    console.error("Failed to decrypt AES key:", error);
    /*
        Failed to decrypt AES key. This likely means the public key uploaded to Meta is incorrect,
        or the private key used here doesn't match.
        Return HTTP status code 421 to refresh the public key on the client (WhatsApp app).
        */
    throw new FlowEndpointException(
      421,
      "Failed to decrypt the request (AES key). Please verify your private key configuration."
    );
  }

  // decrypt flow data using the decrypted AES key and IV
  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");

  const TAG_LENGTH = 16; // GCM auth tag length is 16 bytes
  // Ensure the buffer is long enough to contain data and tag
  if (flowDataBuffer.length < TAG_LENGTH) {
    console.error("Encrypted flow data too short to contain auth tag.");
    throw new FlowEndpointException(
      400, // Bad Request
      "Invalid encrypted flow data format: too short."
    );
  }

  const encrypted_flow_data_body = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encrypted_flow_data_tag = flowDataBuffer.subarray(-TAG_LENGTH);

  try {
    const decipher = crypto.createDecipheriv(
      "aes-128-gcm", // Using AES-128 in GCM mode
      decryptedAesKey,
      initialVectorBuffer
    );
    decipher.setAuthTag(encrypted_flow_data_tag); // Set the auth tag from the end of the encrypted data

    const decryptedJSONString = Buffer.concat([
      decipher.update(encrypted_flow_data_body),
      decipher.final(), // Finalize decryption - verifies the auth tag
    ]).toString("utf-8");

    const decryptedBody = JSON.parse(decryptedJSONString);

    return {
      decryptedBody: decryptedBody,
      aesKeyBuffer: decryptedAesKey,
      initialVectorBuffer,
    };
  } catch (error) {
    console.error("Failed to decrypt flow data or verify auth tag:", error);
    // This can happen if the data was tampered with or keys/IV are mismatched
    throw new FlowEndpointException(
      400, // Bad Request or potentially 421 if it's suspected key issue
      "Failed to decrypt flow data or verify integrity. Request might be invalid or keys mismatched."
    );
  }
};

/**
 * Encrypts the response data to be sent back to the WhatsApp Flow client.
 * Reuses the AES key and a flipped IV from the original request's decryption.
 * @param {object} response The response JSON object (e.g., the next screen definition + data).
 * @param {Buffer} aesKeyBuffer The decrypted AES key buffer from the incoming request.
 * @param {Buffer} initialVectorBuffer The IV buffer from the incoming request.
 * @returns {string} The base64 encoded encrypted response string.
 * @throws {Error} If encryption fails.
 */
const encryptFlowResponse = (response, aesKeyBuffer, initialVectorBuffer) => {
  // flip initial vector
  const flipped_iv = [];
  for (const pair of initialVectorBuffer.entries()) {
    flipped_iv.push(~pair[1]);
  }

  // encrypt response data
  const cipher = crypto.createCipheriv(
    "aes-128-gcm",
    aesKeyBuffer,
    Buffer.from(flipped_iv)
  );
  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
};

/**
 * Custom Exception for WhatsApp Flow endpoint errors with specific status codes.
 */
const FlowEndpointException = class FlowEndpointException extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
  }
};

/**
 * Verifies the x-hub-signature-256 header against the raw request body and App Secret.
 * @param {string} rawBody The raw request body as a string.
 * @param {string} signatureHeader The value of the 'x-hub-signature-256' header (e.g., 'sha256=...').
 * @param {string} appSecret Your Meta App Secret.
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
const isRequestSignatureValid = (rawBody, signatureHeader, appSecret) => {
  if (!appSecret) {
    console.warn(
      "APP_SECRET is not set. Skipping request signature validation. THIS IS INSECURE IN PRODUCTION."
    );
    return true; // Bypass validation if secret is not set (only for development)
  }
  if (!signatureHeader) {
    console.error("Missing 'x-hub-signature-256' header.");
    return false;
  }

  const signature = signatureHeader.replace("sha256=", "");
  const signatureBuffer = Buffer.from(signature, "hex"); // Signature is hex encoded

  const hmac = crypto.createHmac("sha256", appSecret);
  hmac.update(rawBody);
  const digestBuffer = hmac.digest(); // Digest as buffer

  // Use timingSafeEqual to prevent timing attacks
  if (!crypto.timingSafeEqual(digestBuffer, signatureBuffer)) {
    console.error("Error: Request Signature did not match.");
    return false;
  }
  console.log("Request signature verified successfully.");
  return true;
};
import { DecryptedFlowBody } from "./utils";
// Separated screen responses
const SCREEN_RESPONSES = {
  // Screens with error messages
  ERROR_SCREENS: {
    ONBOARDING_CONSENT_SCREEN: {
      screen: "ONBOARDING_CONSENT_SCREEN",
      data: {
        error_message: "Please select an option below.",
      },
    },
    IDENTITY_VERIFICATION_SCREEN: {
      screen: "IDENTITY_VERIFICATION_SCREEN",
      data: {
        error_message: "Invalid National ID format. Please enter 8 digits.",
        national_id_hint: "Format: 12345678",
        employee_name: "Test Employee",
      },
    },
    PIN_VERIFICATION_SCREEN: {
      screen: "PIN_VERIFICATION_SCREEN",
      data: {
        error_message: "Invalid PIN. Please try again.",
      },
    },
    MAIN_MENU_SCREEN: {
      screen: "MAIN_MENU_SCREEN",
      data: {
        error_message: "Invalid selection. Please enter 1, 2, 3, or 4.",
      },
    },
    LOAN_AMOUNT_INPUT_SCREEN: {
      screen: "LOAN_AMOUNT_INPUT_SCREEN",
      data: {
        max_loan_amount: `${25000}`,
        error_message:
          "Invalid amount. Please enter a value between 500 and ${max_loan_amount}.",
      },
    },
    LOAN_TERMS_CONFIRMATION_SCREEN: {
      screen: "LOAN_TERMS_CONFIRMATION_SCREEN",
      data: {
        borrowed_amount: `${5000}`,
        repayment_amount: `${5250}`,
        due_date: "2025-05-18",
        interest_amount: `${250}`,
        error_message: "Please confirm the loan terms to proceed.",
      },
    },
    CUSTOMER_SUPPORT_MENU_SCREEN: {
      screen: "CUSTOMER_SUPPORT_MENU_SCREEN",
      data: {
        error_message: "Invalid selection. Please enter 1, 2, 3, or 4.",
        hr_contact: {
          email: "hr@example.com",
          phone: "+254712345678",
        },
      },
    },
  },

  // Screens without error messages (normal screens)
  NORMAL_SCREENS: {
    PRIVACY_POLICY_SCREEN: {
      screen: "PRIVACY_POLICY_SCREEN",
      data: {},
    },
    PIN_VERIFICATION_SCREEN: {
      screen: "PIN_VERIFICATION_SCREEN",
      data: {
        employee_name: "Test Employee",
        pin_hint: "Format: 1234",
      },
    },
    MAIN_MENU_SCREEN: {
      screen: "MAIN_MENU_SCREEN",
      data: {},
    },
    LOAN_PROCESSING_SUBMITTED_SCREEN: {
      screen: "LOAN_PROCESSING_SUBMITTED_SCREEN",
      data: {
        loan_reference: `LN${Math.floor(Math.random() * 1000000)}`,
      },
    },
    LOAN_AMOUNT_INPUT_SCREEN: {
      screen: "LOAN_AMOUNT_INPUT_SCREEN",
      data: { max_loan_amount: `${25000}` },
    },
    CHECK_LOAN_STATUS_SCREEN: {
      screen: "CHECK_LOAN_STATUS_SCREEN",
      data: {
        borrowed_amount: `${5000}`,
        repaid_amount: `${1000}`,
        remaining_amount: `${4250}`,
        next_payment_date: "2025-06-15",
      },
    },
    VIEW_REPAYMENT_SCHEDULE_SCREEN: {
      screen: "VIEW_REPAYMENT_SCHEDULE_SCREEN",
      data: {
        due_date: "2025-06-15",
        repayment_amount: `${3150}`,
      },
    },
    CUSTOMER_SUPPORT_MENU_SCREEN: {
      screen: "CUSTOMER_SUPPORT_MENU_SCREEN",
      data: {},
    },
    FAQ_SCREEN: {
      screen: "FAQ_SCREEN",
      data: {
        faqs: [
          {
            question: "Who is eligible for a Kwikash salary advance?",
            answer: "You are eligible if your employer has enrolled you...",
          },
        ],
      },
    },
  },
  PROCESSED_SCREENS: {
    IDENTITY_VERIFICATION_SCREEN: function (nationalId) {
      if (!nationalId)
        return SCREEN_RESPONSES.ERROR_SCREENS.IDENTITY_VERIFICATION_SCREEN;

      // Validate National ID
      const idIsValid = /^\d{8}$/.test(nationalId);

      if (!idIsValid)
        return SCREEN_RESPONSES.ERROR_SCREENS.IDENTITY_VERIFICATION_SCREEN;

      const idVerified = nationalId === "12345678";

      if (!idVerified)
        return SCREEN_RESPONSES.ERROR_SCREENS.IDENTITY_VERIFICATION_SCREEN;

      return SCREEN_RESPONSES.NORMAL_SCREENS.PIN_VERIFICATION_SCREEN;
    },
    PIN_VERIFICATION_SCREEN: function (pin) {
      if (!pin) return SCREEN_RESPONSES.ERROR_SCREENS.PIN_VERIFICATION_SCREEN;

      const pinIsValid = /^\d{4}$/.test(pin);

      if (!pinIsValid)
        return SCREEN_RESPONSES.ERROR_SCREENS.PIN_VERIFICATION_SCREEN;

      const pinVerified = pin === "1234";

      if (!pinVerified)
        return SCREEN_RESPONSES.ERROR_SCREENS.PIN_VERIFICATION_SCREEN;

      return SCREEN_RESPONSES.NORMAL_SCREENS.MAIN_MENU_SCREEN;
    },
    MAIN_MENU_SCREEN: function (selection) {
      if (!selection) return SCREEN_RESPONSES.ERROR_SCREENS.MAIN_MENU_SCREEN;

      const selectionIsValid = /^[1-4]$/.test(selection);

      if (!selectionIsValid)
        return SCREEN_RESPONSES.ERROR_SCREENS.MAIN_MENU_SCREEN;

      const selectedOption = parseInt(selection, 10);

      switch (selectedOption) {
        case 1:
          return SCREEN_RESPONSES.NORMAL_SCREENS.LOAN_AMOUNT_INPUT_SCREEN;
        case 2:
          return SCREEN_RESPONSES.NORMAL_SCREENS.CHECK_LOAN_STATUS_SCREEN;
        case 3:
          return SCREEN_RESPONSES.NORMAL_SCREENS.VIEW_REPAYMENT_SCHEDULE_SCREEN;
        case 4:
          return SCREEN_RESPONSES.NORMAL_SCREENS.CUSTOMER_SUPPORT_MENU_SCREEN;
        default:
          console.warn("Invalid menu selection:", selectedOption);
          return SCREEN_RESPONSES.ERROR_SCREENS.MAIN_MENU_SCREEN;
      }
    },

    LOAN_AMOUNT_INPUT_SCREEN: function (amount) {
      if (amount !== undefined && amount !== null) {
        const requestedAmount = parseFloat(amount);
        console.log(`Received requested loan amount: ${requestedAmount}`);

        const maxLoan = 25000;
        const loanIsValid =
          !isNaN(requestedAmount) &&
          requestedAmount > 0 &&
          requestedAmount <= maxLoan;

        if (loanIsValid) {
          const interestRate = 0.05;
          const repaymentAmount = requestedAmount * (1 + interestRate);
          const dueDate = new Date();
          dueDate.setDate(dueDate.getDate() + 30);
          const formattedDueDate = dueDate.toISOString().split("T")[0];

          return {
            screen: "LOAN_TERMS_CONFIRMATION_SCREEN",
            data: {
              borrowed_amount: `${requestedAmount}`,
              repayment_amount: `${repaymentAmount}`,
              due_date: `${formattedDueDate}`,
              interest_amount: `${requestedAmount * interestRate}`,
            },
          };
        }
        console.warn("Invalid loan amount requested:", `${requestedAmount}`);
        return {
          screen: "LOAN_AMOUNT_INPUT_SCREEN",
          data: {
            max_loan_amount: `${maxLoan}`,
            error_message: `Invalid amount. Please enter a value between 1 and ${maxLoan}.`,
          },
        };
      }
      console.warn(
        `Missing or invalid requested_amount in payload:LOAN_AMOUNT_INPUT_SCREEN`
      );
      return SCREEN_RESPONSES.ERROR_SCREENS.LOAN_AMOUNT_INPUT_SCREEN;
    },
    VIEW_REPAYMENT_SCHEDULE_SCREEN: function (action) {
      if (action === "request_schedule_text") {
        console.log(
          "User requested schedule as text. Triggering text message."
        );
      }
      if (action === "request_schedule_pdf") {
        console.log(
          "User requested schedule as PDF. Triggering PDF generation."
        );
      }
      if (action === "schedule_screen_acknowledged") {
        console.log("User acknowledged repayment schedule screen.");
      }
      return SCREEN_RESPONSES.NORMAL_SCREENS.MAIN_MENU_SCREEN;
    },
    CUSTOMER_SUPPORT_MENU_SCREEN: function (selection) {
      if (!selection)
        return SCREEN_RESPONSES.ERROR_SCREENS.CUSTOMER_SUPPORT_MENU_SCREEN;

      const selectionIsValid = /^[1-4]$/.test(selection);

      if (!selectionIsValid)
        return SCREEN_RESPONSES.ERROR_SCREENS.CUSTOMER_SUPPORT_MENU_SCREEN;

      const selectedOption = parseInt(selection, 10);

      switch (selectedOption) {
        case 1:
          return SCREEN_RESPONSES.NORMAL_SCREENS.FAQ_SCREEN;
        case 2:
          return SCREEN_RESPONSES.NORMAL_SCREENS.FAQ_SCREEN;
        case 3:
          return SCREEN_RESPONSES.NORMAL_SCREENS.FAQ_SCREEN;
        case 4:
          return SCREEN_RESPONSES.NORMAL_SCREENS.FAQ_SCREEN;
        case 5:
          return SCREEN_RESPONSES.NORMAL_SCREENS.MAIN_MENU_SCREEN;
        default:
          console.warn("Invalid customer support selection:", selectedOption);
          return SCREEN_RESPONSES.ERROR_SCREENS.CUSTOMER_SUPPORT_MENU_SCREEN;
      }
    },
  },
};

// Usage examples:
// const hasError = SCREEN_RESPONSES.hasError('PIN_VERIFICATION_SCREEN'); // true
// const allErrors = SCREEN_RESPONSES.getAllErrorMessages();
// const specificScreen = SCREEN_RESPONSES.getScreen('CHECK_LOAN_STATUS_SCREEN');

async function getNextScreen(decryptedBody) {
  const { screen, data, version, action, flow_token } = decryptedBody;

  // Handle health check request
  if (action === "ping") {
    return {
      data: {
        status: "active",
      },
    };
  }

  // Handle error notification
  if (data?.error || data?.error_message) {
    console.error(
      "Received client error:",
      data?.error_message || data?.error,
      data
    );
    return {
      screen,
      data: {
        error_message:
          "System temporarily unavailable. Please try again later.",
      },
    };
  }

  // Handle initial request when opening the flow
  if (action === "INIT") {
    return {
      screen: "ONBOARDING_CONSENT_SCREEN",
      version: version,
      data: {},
    };
  }

  // Handle navigation events
  if (action === "navigate") {
    const nextScreen = data.next?.name;

    return {
      screen: nextScreen,
      version: version,
      data: {},
    };
  }

  // Handle completion events
  if (action === "complete") {
    console.log(`User completed ${screen} screen.`);

    return {
      data: {
        acknowledged: true,
      },
    };
  }

  if (action === "data_exchange") {
    switch (screen) {
      case "ONBOARDING_CONSENT_SCREEN":
        return SCREEN_RESPONSES.ERROR_SCREENS.ONBOARDING_CONSENT_SCREEN;

      case "IDENTITY_VERIFICATION_SCREEN":
        return SCREEN_RESPONSES.PROCESSED_SCREENS.IDENTITY_VERIFICATION_SCREEN(
          data?.national_id
        );

      case "PIN_VERIFICATION_SCREEN":
        return SCREEN_RESPONSES.PROCESSED_SCREENS.PIN_VERIFICATION_SCREEN(
          data?.pin
        );

      case "MAIN_MENU_SCREEN":
        return SCREEN_RESPONSES.PROCESSED_SCREENS.MAIN_MENU_SCREEN(
          data?.selection
        );

      case "LOAN_AMOUNT_INPUT_SCREEN":
        return SCREEN_RESPONSES.PROCESSED_SCREENS.LOAN_AMOUNT_INPUT_SCREEN(
          data?.requested_amount
        );

      case "LOAN_TERMS_CONFIRMATION_SCREEN":
        return SCREEN_RESPONSES.NORMAL_SCREENS.LOAN_PROCESSING_SUBMITTED_SCREEN;

      case "LOAN_PROCESSING_SUBMITTED_SCREEN":
        return SCREEN_RESPONSES.NORMAL_SCREENS.CHECK_LOAN_STATUS_SCREEN;

      case "CHECK_LOAN_STATUS_SCREEN":
        return SCREEN_RESPONSES.NORMAL_SCREENS.MAIN_MENU_SCREEN;

      case "VIEW_REPAYMENT_SCHEDULE_SCREEN":
        return SCREEN_RESPONSES.PROCESSED_SCREENS.VIEW_REPAYMENT_SCHEDULE_SCREEN(
          data?.action
        );

      case "FAQ_SCREEN":
        return SCREEN_RESPONSES.NORMAL_SCREENS.CUSTOMER_SUPPORT_MENU_SCREEN;

      case "CUSTOMER_SUPPORT_MENU_SCREEN":
        return SCREEN_RESPONSES.PROCESSED_SCREENS.CUSTOMER_SUPPORT_MENU_SCREEN(
          data?.selection
        );

      default:
        return SCREEN_RESPONSES.ERROR_SCREENS.MAIN_MENU_SCREEN;
    }
  }

  console.error("Unhandled request body:", decryptedBody);
  throw new Error(
    "Unhandled endpoint request. Make sure you handle the request action & screen."
  );
}

module.exports = {
  decryptFlowRequest,
  encryptFlowResponse,
  FlowEndpointException,
  isRequestSignatureValid,
  getNextScreen,
};
