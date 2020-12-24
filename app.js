const openssl = require("openssl-nodejs");
const path = require("path");
var SignedXml = require("xml-crypto").SignedXml;
var fs = require("fs");
var FileKeyInfo = require("xml-crypto").FileKeyInfo;

const func = async () => {
  await openssl(
    `openssl pkcs12 -in ${path.normalize(
      "C:\\Gescom\\agil.pfx"
    )} -out ${path.normalize(
      "C:\\Gescom\\key.pem"
    )} -nodes -password pass:agil2061`,
    (e, buffer) => console.log("e: ", e, " b: ", buffer)
  );
  return;
};

const func2 = async () => {
  // await func();
  // var xml =
  // "<library>" +
  // "<book>" +
  // "<name>Harry Potter</name>" +
  // "</book>" +
  // "</library>";
  var xml = await fs.readFileSync(
    path.normalize("C:\\Gescom\\GID\\pesquisaEstoqueGID.xml"),
    "utf8"
  );

  var sig = new SignedXml();
  var transforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  ];

  sig.addReference("//*[local-name(.)='PESQUISAR_ESTOQUE']", transforms);
  sig.signingKey = fs.readFileSync(path.normalize("C:\\Gescom\\key.pem"));
  sig.canonicalizationAlgorithm =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
  sig.keyInfoProvider = new FileKeyInfo(path.normalize("C:\\Gescom\\key.pem"));
  sig.computeSignature(xml, {
    location: {
      reference: "//*[local-name(.)='infPesquisarEstoque']",
      action: "after",
    },
  });  

  fs.writeFileSync(`${__dirname}\\signed.xml`, sig.getSignedXml());
};

function getX509Cert() {
  let cert = fs.readFileSync(path.normalize("C:\\Gescom\\key.pem")).toString()
  return cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/\s/g, '').replace(/(\r\n\t|\n|\r\t)/gm, '')
}

// some other stuff

function KeyProvider() {
  this.getKeyInfo = function () {
    return `<X509Data><X509Certificate>${getX509Cert()}</X509Certificate></X509Data>`
  }
}

func2();
