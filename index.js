const crypto = require("crypto");

const replacementContent = "Will be replaced with HMAC of request body";

function hmac(body, url, options) {
  let content = options.removeWhitespace
    ? JSON.stringify(JSON.parse(body))
    : body;
  const timestamp = Math.round(Date.now() / 1000);
  const signature = crypto.createHmac(options.algorithm, options.key);
  signature.update([url, timestamp, content].join(","), "utf8");
  return `t=${timestamp},s=${signature.digest(options.encoding)}`;
}

function replaceWithHMAC(content, body, url) {
  return content.replace(
    new RegExp(replacementContent + " \\(([a-f0-9]+)\\)", "g"),
    (match, hex) => {
      const options = JSON.parse(Buffer.from(hex, "hex").toString("utf-8"));
      return hmac(body, url, options);
    }
  );
}

module.exports.templateTags = [
  {
    name: "webhookSignature",
    displayName: "Webhook Signature",
    description: "HMAC of request body with timestamp",
    args: [
      {
        displayName: "Algorithm",
        type: "enum",
        options: [
          { displayName: "MD5", value: "md5" },
          { displayName: "SHA1", value: "sha1" },
          { displayName: "SHA256", value: "sha256" },
          { displayName: "SHA512", value: "sha512" },
        ],
      },
      {
        displayName: "Digest Encoding",
        description: "The encoding of the output",
        type: "enum",
        options: [
          { displayName: "Base64", value: "base64" },
          { displayName: "Hexadecimal", value: "hex" },
        ],
      },
      {
        displayName: "Remove whitespace from JSON",
        description:
          "Parse and stringify JSON request body to remove any whitespace",
        type: "enum",
        options: [
          { displayName: "Yes", value: true },
          { displayName: "No", value: false },
        ],
      },
      {
        displayName: "HMAC Secret Key",
        type: "string",
        placeholder: "HMAC Secret Key",
      },
    ],
    async run(context, algorithm, encoding, removeWhitespace, key = "") {
      if (encoding !== "hex" && encoding !== "base64") {
        throw new Error(
          `Invalid encoding ${encoding}. Choices are hex, base64`
        );
      }

      const options = { key, algorithm, removeWhitespace, encoding };

      return (
        replacementContent +
        " (" +
        Buffer.from(JSON.stringify(options)).toString("hex") +
        ")"
      );
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
