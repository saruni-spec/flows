require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");

const router = express.Router();
router.use(
  bodyParser.json({
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf.toString(encoding || "utf8");
    },
  })
);

// Variables for WhatsApp API
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const WHATSAPP_API_URL = "https://graph.facebook.com/v17.0/";
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID;

// Webhook verification for WhatsApp
router.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  // Check if token and mode are present
  if (mode && token) {
    // Check the mode and token
    if (mode === "subscribe" && token === process.env.VERIFY_TOKEN) {
      // Respond with the challenge token from the request
      console.log("WEBHOOK_VERIFIED");
      return res.status(200).send(challenge);
    }
  }
  // Respond with '403 Forbidden' if verify tokens do not match
  return res.sendStatus(403);
});

// Webhook for receiving messages
router.post("/webhook", async (req, res) => {
  try {
    const { body } = req;

    // Debug the full webhook payload (helpful for understanding the structure)
    console.log("Webhook received:", JSON.stringify(body, null, 2));

    // Check if this is a WhatsApp message
    if (body.object === "whatsapp_business_account") {
      if (
        body.entry &&
        body.entry[0].changes &&
        body.entry[0].changes[0].value.messages &&
        body.entry[0].changes[0].value.messages[0]
      ) {
        const phoneNumber = body.entry[0].changes[0].value.messages[0].from;
        const message = body.entry[0].changes[0].value.messages[0].text?.body;
        const senderName =
          body.entry[0].changes[0].value.contacts[0].profile.name;

        console.log(
          `New message from ${phoneNumber},${senderName}: ${message}`
        );

        //check if the message is yes(any case)
        let templateName;
        let components = [];
        const messageLowerCase = message.toLowerCase();
        if (messageLowerCase === "yes" || messageLowerCase == "info") {
          // Send template message as automated reply - using the Kwikash template
          templateName = "onboarding";

          components = [
            {
              type: "button",
              sub_type: "flow",
              index: "0",
              parameters: [
                {
                  type: "action",
                  action: {},
                },
              ],
            },
          ];

          await sendWhatsAppMessage(
            phoneNumber,
            "", // No text message when using template
            true, // Use template = true
            templateName,
            "en", // Template language
            components // Template components with variables
          );
        } else {
          // Send template message as automated reply - using the Kwikash template
          templateName = "kwiskash_opt_in";
          components = [
            {
              type: "body",
              parameters: [
                {
                  type: "text",
                  text: senderName || "Dear Customer", // Fallback if name is not available
                },
              ],
            },
          ];

          await sendWhatsAppMessage(
            phoneNumber,
            "", // No text message when using template
            true, // Use template = true
            templateName,
            "en_US", // Template language
            components // Template components with variables
          );
        }

        // Components for the Kwikash template with the name variable

        return res.sendStatus(200);
      }
    }

    return res.sendStatus(200);
  } catch (error) {
    console.error(`Error processing webhook: ${error}`);
    return res.sendStatus(500);
  }
});

// Function to send WhatsApp messages (text or template)
async function sendWhatsAppMessage(
  to,
  message,
  useTemplate = false,
  templateName = null,
  templateLanguage = "en_US",
  components = []
) {
  try {
    let requestBody = {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: to,
    };

    // If using a template
    if (useTemplate && templateName) {
      requestBody.type = "template";
      requestBody.template = {
        name: templateName,
        language: {
          code: templateLanguage,
        },
      };

      // Add components if provided (for template variables)
      if (components.length > 0) {
        requestBody.template.components = components;
      }
    } else {
      // Regular text message
      requestBody.type = "text";
      requestBody.text = { body: message };
    }

    console.log(`Sending message to ${to}:`, requestBody);

    const response = await axios.post(
      `${WHATSAPP_API_URL}${PHONE_NUMBER_ID}/messages`,
      requestBody,
      {
        headers: {
          Authorization: `Bearer ${WHATSAPP_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log(`Message sent successfully to ${to}`);
    return response.data;
  } catch (error) {
    console.error(
      `Error sending WhatsApp message: ${
        error.response?.data
          ? JSON.stringify(error.response.data)
          : error.message
      }`
    );
    throw error;
  }
}

// Export the router
module.exports = router;
