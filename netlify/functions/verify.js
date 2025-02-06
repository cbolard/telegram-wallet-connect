// netlify/functions/verify.js

import nacl from "tweetnacl";
import bs58 from "bs58";
import fetch from "node-fetch";

export async function handler(event, context) {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method Not Allowed" }),
    };
  }

  try {
    const { wallet, challenge, signature, chatId } = JSON.parse(event.body);

    if (!wallet || !challenge || !signature) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message: "Missing wallet, challenge or signature parameter",
        }),
      };
    }

    // Décodage de la signature (base64 → Uint8Array)
    const signatureUint8 = Uint8Array.from(Buffer.from(signature, "base64"));

    // Encodage du challenge en Uint8Array
    const messageUint8 = new TextEncoder().encode(challenge);

    // Décodage de la clé publique (base58 → Uint8Array)
    const publicKeyUint8 = bs58.decode(wallet);

    // Vérification de la signature avec tweetnacl
    const verified = nacl.sign.detached.verify(
      messageUint8,
      signatureUint8,
      publicKeyUint8
    );

    if (verified) {
      // Si chatId est fourni, envoi d'un message via l'API Telegram
      if (chatId) {
        const botToken = process.env.TELEGRAM_BOT_TOKEN;
        const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
        await fetch(telegramUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: chatId,
            text: "✅ Wallet vérifié et connecté !",
          }),
        });
      }

      return {
        statusCode: 200,
        body: JSON.stringify({
          success: true,
          message: "Wallet verified and connected",
        }),
      };
    } else {
      return {
        statusCode: 400,
        body: JSON.stringify({
          success: false,
          message: "Invalid signature",
        }),
      };
    }
  } catch (error) {
    console.error("Error verifying signature:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        success: false,
        message: "Internal server error",
        error: error.message,
      }),
    };
  }
}
