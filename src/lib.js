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

const SCREEN_RESPONSES = {
  ONBOARDING_CONSENT_SCREEN: {
    screen: "ONBOARDING_CONSENT_SCREEN",
    data: {
      // Typically no data needed for initial screen
      // Error message can be included if validation fails
      error_message: "Please select an option below.",
    },
  },
  PRIVACY_POLICY_SCREEN: {
    screen: "PRIVACY_POLICY_SCREEN",
    data: {
      // Terminal screen - usually no response data needed
    },
  },
  IDENTITY_VERIFICATION_SCREEN: {
    screen: "IDENTITY_VERIFICATION_SCREEN",
    data: {
      // Data for error cases
      error_message: "Invalid National ID format. Please enter 8 digits.",
      national_id_hint: "Format: 12345678",
      // Data for successful verification
      employee_name: "Test Employee", // Would come from your backend
    },
  },
  PIN_VERIFICATION_SCREEN: {
    screen: "PIN_VERIFICATION_SCREEN",
    data: {
      error_message: "Invalid PIN. Please try again.",
      // Could include remaining attempts if you track that
      attempts_remaining: 2,
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
      max_loan_amount: 25000, // Would come from your backend
      error_message:
        "Invalid amount. Please enter a value between 500 and ${max_loan_amount}.",
    },
  },
  LOAN_TERMS_CONFIRMATION_SCREEN: {
    screen: "LOAN_TERMS_CONFIRMATION_SCREEN",
    data: {
      borrowed_amount: 5000, // Would come from previous step
      repayment_amount: 5250, // Calculated
      due_date: "2025-05-18", // Calculated
      interest_amount: 250, // Calculated
      error_message: "Please confirm the loan terms to proceed.",
    },
  },
  LOAN_PROCESSING_SUBMITTED_SCREEN: {
    screen: "LOAN_PROCESSING_SUBMITTED_SCREEN",
    data: {
      loan_reference: "LN123456", // Generated by your backend
      // Terminal screen - usually no additional data needed
    },
  },
  CHECK_LOAN_STATUS_SCREEN: {
    screen: "CHECK_LOAN_STATUS_SCREEN",
    data: {
      borrowed_amount: 5000, // From your backend
      repaid_amount: 1000, // From your backend
      remaining_amount: 4250, // Calculated
      // Could include next payment date etc.
      next_payment_date: "2025-06-15",
    },
  },
  VIEW_REPAYMENT_SCHEDULE_SCREEN: {
    screen: "VIEW_REPAYMENT_SCHEDULE_SCREEN",
    data: {
      due_date: "2025-05-18", // From your backend
      repayment_amount: 5250, // From your backend
      // Could include full schedule if needed
      full_schedule: [
        { due_date: "2025-05-18", amount: 5250 },
        { due_date: "2025-06-18", amount: 5250 },
      ],
    },
  },
  CUSTOMER_SUPPORT_MENU_SCREEN: {
    screen: "CUSTOMER_SUPPORT_MENU_SCREEN",
    data: {
      error_message: "Invalid selection. Please enter 1, 2, 3, or 4.",
      // Could include support contact info
      hr_contact: {
        email: "hr@example.com",
        phone: "+254712345678",
      },
    },
  },
  FAQ_SCREEN: {
    screen: "FAQ_SCREEN",
    data: {
      // Terminal screen - usually no response data needed
      // Could include dynamic FAQ content if needed
      faqs: [
        {
          question: "Who is eligible for a Kwikash salary advance?",
          answer: "You are eligible if your employer has enrolled you...",
        },
      ],
    },
  },
};

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
      screen, // Stay on the same screen
      data: {
        error_message:
          "System temporarily unavailable. Please try again later.",
        // You might need to add screen-specific fields here
      },
    };
  }

  // Handle initial request when opening the flow
  if (action === "INIT") {
    return {
      screen: "ONBOARDING_CONSENT_SCREEN",
      version: version, // Use the version from the request
      data: {},
    };
  }

  // Handle navigation events
  if (action === "navigate") {
    // The 'navigate' action payload contains the next screen name
    const nextScreen = data.next?.name;
    console.log("Navigate action, next screen:", nextScreen);

    return {
      screen: nextScreen,
      version: version,
      data: {},
    };
  }

  // Handle completion events
  if (action === "complete") {
    console.log(`User completed ${screen} screen.`);
    // Terminal screen with 'complete' action - no next screen in flow
    // Return minimal response to signal completion
    return {
      data: {
        acknowledged: true,
      },
    };
  }

  if (action === "data_exchange") {
    // Handle the request based on the current screen
    switch (screen) {
      case "ONBOARDING_CONSENT_SCREEN":
        console.warn(`Received unexpected data_exchange event on ${screen}`);
        return {
          screen: screen, // Stay on the same screen
          data: {
            error_message: "Please select an option below.",
          },
        };

      case "IDENTITY_VERIFICATION_SCREEN":
        if (data?.national_id) {
          const nationalId = data.national_id;
          console.log(`Received National ID: ${nationalId}`);

          // Validate National ID
          const idIsValid = /^\d{8}$/.test(nationalId);

          if (idIsValid) {
            // Simulate backend verification
            const idVerified = nationalId === "12345678";

            if (idVerified) {
              return {
                screen: "PIN_VERIFICATION_SCREEN",
                data: {
                  employee_name: "Test Employee",
                },
              };
            } else {
              return {
                screen: "IDENTITY_VERIFICATION_SCREEN",
                data: {
                  employee_name: "Failed",
                },
              };
            }
          } else {
            return {
              screen: "IDENTITY_VERIFICATION_SCREEN",
              data: {
                employee_name: "Failed invalid",
              },
            };
          }
        } else {
          console.warn(`Invalid payload format on ${screen}:`, data);
          return {
            screen: "IDENTITY_VERIFICATION_SCREEN",
            data: {
              employee_name: "Failed invalid form",
            },
          };
        }

      case "PIN_VERIFICATION_SCREEN":
        if (data?.pin) {
          const pin = data.pin;
          console.log(`Received PIN: ${pin}`);

          const pinIsValid = pin === "1234"; // Simulate PIN validation

          if (pinIsValid) {
            return {
              screen: "MAIN_MENU_SCREEN",
              data: {},
            };
          } else {
            console.warn("Invalid PIN entered.");
            return {
              screen: "PIN_VERIFICATION_SCREEN",
              data: {
                error_message: "Invalid PIN. Please try again.",
              },
            };
          }
        } else {
          console.warn(`Missing or invalid PIN in payload:`, data);
          return {
            screen: screen,
            data: {
              error_message: "Please enter your PIN.",
            },
          };
        }

      case "MAIN_MENU_SCREEN":
        if (data?.selection !== undefined && data?.selection !== null) {
          const selection = parseInt(data.selection, 10);
          console.log(`Received Main Menu selection: ${selection}`);

          // Route based on selection
          switch (selection) {
            case 1:
              return {
                screen: "LOAN_AMOUNT_INPUT_SCREEN",
                data: { max_loan_amount: 25000 },
              };
            case 2:
              return {
                screen: "CHECK_LOAN_STATUS_SCREEN",
                data: {
                  borrowed_amount: 6000,
                  repaid_amount: 3000,
                  remaining_amount: 3150,
                },
              };
            case 3:
              return {
                screen: "VIEW_REPAYMENT_SCHEDULE_SCREEN",
                data: {
                  due_date: "2025-06-15",
                  repayment_amount: 3150,
                },
              };
            case 4:
              return {
                screen: "CUSTOMER_SUPPORT_MENU_SCREEN",
                data: {},
              };
            default:
              console.warn("Invalid menu selection:", selection);
              return {
                screen: "MAIN_MENU_SCREEN",
                data: {
                  error_message:
                    "Invalid selection. Please enter 1, 2, 3, or 4.",
                },
              };
          }
        } else {
          console.warn(`Missing or invalid selection in payload:`, data);
          return {
            screen: screen,
            data: {
              error_message: "Please enter a valid option (1-4).",
            },
          };
        }

      case "LOAN_AMOUNT_INPUT_SCREEN":
        if (
          data?.requested_amount !== undefined &&
          data?.requested_amount !== null
        ) {
          const requestedAmount = parseFloat(data.requested_amount);
          console.log(`Received requested loan amount: ${requestedAmount}`);

          const maxLoan = 25000;
          const loanIsValid =
            !isNaN(requestedAmount) &&
            requestedAmount > 0 &&
            requestedAmount <= maxLoan;

          if (loanIsValid) {
            const interestRate = 0.05; // 5%
            const repaymentAmount = requestedAmount * (1 + interestRate);
            const dueDate = new Date();
            dueDate.setDate(dueDate.getDate() + 30);
            const formattedDueDate = dueDate.toISOString().split("T")[0];

            return {
              screen: "LOAN_TERMS_CONFIRMATION_SCREEN",
              data: {
                borrowed_amount: requestedAmount,
                repayment_amount: repaymentAmount,
                due_date: formattedDueDate,
                interest_amount: requestedAmount * interestRate,
              },
            };
          } else {
            console.warn("Invalid loan amount requested:", requestedAmount);
            return {
              screen: "LOAN_AMOUNT_INPUT_SCREEN",
              data: {
                max_loan_amount: maxLoan,
                error_message: `Invalid amount. Please enter a value between 1 and ${maxLoan}.`,
              },
            };
          }
        } else {
          console.warn(`Missing or invalid requested_amount in payload:`, data);
          return {
            screen: screen,
            data: {
              max_loan_amount: 25000,
              error_message: "Please enter a valid amount.",
            },
          };
        }

      case "LOAN_TERMS_CONFIRMATION_SCREEN":
        if (data?.action === "confirm_loan_terms") {
          console.log("Loan terms confirmed.");
          const loanReference = `LN${Math.floor(Math.random() * 1000000)}`;

          return {
            screen: "LOAN_PROCESSING_SUBMITTED_SCREEN",
            data: { loan_reference: loanReference },
          };
        } else {
          console.warn(`Unexpected payload or action:`, data);
          return {
            screen: screen,
            data: {
              error_message: "Please confirm the loan terms to proceed.",
            },
          };
        }

      case "LOAN_PROCESSING_SUBMITTED_SCREEN":
      case "CHECK_LOAN_STATUS_SCREEN":
      case "VIEW_REPAYMENT_SCHEDULE_SCREEN":
      case "FAQ_SCREEN":
        // Terminal screens
        console.log(`User action on terminal screen: ${screen}`);
        console.log("Terminal screen payload:", data);

        // Handle specific actions for terminal screens
        if (screen === "VIEW_REPAYMENT_SCHEDULE_SCREEN") {
          if (data?.action === "request_schedule_text") {
            console.log(
              "User requested schedule as text. Triggering text message."
            );
          } else if (data?.action === "request_schedule_pdf") {
            console.log(
              "User requested schedule as PDF. Triggering PDF generation."
            );
          } else if (data?.action === "schedule_screen_acknowledged") {
            console.log("User acknowledged schedule screen.");
          }
        } else if (
          screen === "LOAN_PROCESSING_SUBMITTED_SCREEN" &&
          data?.action === "acknowledge_submission_viewed"
        ) {
          console.log("User acknowledged submission screen.");
        } else if (
          screen === "CHECK_LOAN_STATUS_SCREEN" &&
          data?.action === "status_screen_acknowledged"
        ) {
          console.log("User acknowledged status screen.");
        } else if (
          screen === "FAQ_SCREEN" &&
          data?.action === "faq_screen_acknowledged"
        ) {
          console.log("User acknowledged FAQ screen.");
        }

        // Return minimal response for terminal screens
        return {
          data: {
            acknowledged: true,
          },
        };

      case "CUSTOMER_SUPPORT_MENU_SCREEN":
        if (data?.selection !== undefined && data?.selection !== null) {
          const selection = parseInt(data.selection, 10);
          console.log(`Received Support Menu selection: ${selection}`);

          switch (selection) {
            case 1:
              console.log(
                "User requested PIN reset. Triggering external action."
              );
              // No next screen defined for this action
              return {
                data: {
                  acknowledged: true,
                },
              };
            case 2:
              return {
                screen: "FAQ_SCREEN",
                data: {},
              };
            case 3:
              console.log(
                "User requested Contact HR info. Triggering external action."
              );
              return {
                data: {
                  acknowledged: true,
                },
              };
            case 4:
              console.log(
                "User requested to Speak to an agent. Triggering external action."
              );
              return {
                data: {
                  acknowledged: true,
                },
              };
            default:
              console.warn("Invalid support menu selection:", selection);
              return {
                screen: "CUSTOMER_SUPPORT_MENU_SCREEN",
                data: {
                  error_message:
                    "Invalid selection. Please enter 1, 2, 3, or 4.",
                },
              };
          }
        } else {
          console.warn(`Missing or invalid selection in payload:`, data);
          return {
            screen: screen,
            data: {
              error_message: "Please enter a valid option (1-4).",
            },
          };
        }

      default:
        console.error(`Unknown screen ID received: ${screen}`);
        return {
          screen: "MAIN_MENU_SCREEN",
          data: {
            error_message:
              "An unexpected error occurred. Please try again from the main menu.",
          },
        };
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
  SCREEN_RESPONSES,
  getNextScreen,
};
