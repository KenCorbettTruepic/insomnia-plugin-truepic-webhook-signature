const crypto = require("crypto");

const replacementContent = "Will be replaced with Truepic Webhook Signature";

function hmac(body, url, key) {
  const content = JSON.stringify(JSON.parse(body));
  const timestamp = Math.round(Date.now() / 1000);
  const signature = crypto.createHmac("sha256", key);
  signature.update([url, timestamp, content].join(","), "utf8");
  return `t=${timestamp},s=${signature.digest("base64")}`;
}

function replaceWithHMAC(content, body, url) {
  try {
    return content.replace(
      new RegExp(`${replacementContent} \\(([a-f0-9]+)\\)`, "g"),
      (match, hex) => {
        console.log({ match, hex });
        const key = Buffer.from(hex, "hex").toString("utf-8");
        return hmac(body, url, key);
      }
    );
  } catch (e) {
    console.error(e);
    throw e;
  }
}

module.exports.templateTags = [
  {
    name: "truepicWebhookSignature",
    displayName: "Truepic Webhook Signature",
    description: "HMAC of request body with timestamp and a secret key",
    args: [
      {
        displayName: "Secret Key",
        type: "string",
        placeholder: "Secret Key",
      },
    ],
    async run(context, key = "") {
      if (!key) {
        throw new Error(
          `You must provide your HMAC secret key to use this tag.`
        );
      }

      return `${replacementContent} (${Buffer.from(key).toString("hex")})`;
    },
  },
];

module.exports.requestHooks = [
  async (context) => {
    const body = context.request.getBody();
    const url = context.request.getUrl();
    let bodyText = body.text || "";
    context.request.getHeaders().forEach((h) => {
      if (h.value.indexOf(replacementContent) !== -1) {
        context.request.setHeader(
          h.name,
          replaceWithHMAC(h.value, bodyText, url)
        );
      }
    });
    context.request.getParameters().forEach((p) => {
      if (p.value.indexOf(replacementContent) !== -1) {
        context.request.setParameter(
          p.name,
          replaceWithHMAC(p.value, bodyText, url)
        );
      }
    });
  },
];
