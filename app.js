const path = require("path");
var SignedXml = require("xml-crypto").SignedXml;
var fs = require("fs");
var forge = require("node-forge");
var FileKeyInfo = require("xml-crypto").FileKeyInfo;

function MyKeyInfo(key) {
  this.getKeyInfo = function () {
    return (
      "<X509Data><X509Certificate>" + key + "</X509Certificate></X509Data>"
    );
  };
}

async function test() {
  const pem = require("pem");
  const fs = require("fs");
  const pfx = fs.readFileSync("C:\\Gescom\\certificado novo.pfx");

  await pem.readPkcs12(pfx, { p12Password: "35111439" }, async (err, cert) => {
    if (err) {
      throw err;
    }

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
    sig.signingKey = cert;
    sig.canonicalizationAlgorithm =
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    let certificado = cert.cert
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "")
      .replace(/\n/g, "")
      .replace(/\r/g, "");

    // console.log(certificado);
    sig.keyInfoProvider = new MyKeyInfo(certificado);
    sig.computeSignature(xml, {
      location: {
        reference: "//*[local-name(.)='infPesquisarEstoque']",
        action: "after",
      },
    });

    fs.writeFileSync(`${__dirname}\\signed.xml`, sig.getSignedXml());
  });
}

async function testSoap() {
  var url = "https://secweb.procergs.com.br/cdv/IntegracaoGidSoap";
  const xml = fs.readFileSync(`${__dirname}\\signed.xml`, "utf8");
  const soapRequest = require("easy-soap-request");
  var convert = require("xml-js");

  const sampleHeaders = {
    "user-agent": "sampleTest",
    "Content-Type": "text/xml;charset=UTF-8",
    
  };

  (async () => {
    const { response } = await soapRequest({
      url: url,
      headers: sampleHeaders,
      xml: xml,
    });
    const { headers, body, statusCode } = response;

    var result = convert.xml2json(body, { compact: true, spaces: 4 });
    fs.writeFileSync(`${__dirname}\\res.json`, result);
  })();
}

// test();
testSoap();
