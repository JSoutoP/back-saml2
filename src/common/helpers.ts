export function getSAMLLogout(
  id: string,
  issueInstant: string,
  nameId: string,
  spNameQualifier: string,
  issuer: string,
  reason: string = 'urn:oasis:names:tc:SAML:2.0:logout:user',
) {
  const destination =
    process.env.DESTINATION ||
    'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider';
  // Puedes agregar más variables de entorno si lo necesitas
  return `
<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                      xmlns:eidas="http://eidas.europa.eu/saml-extensions"
                      xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                      Destination="${destination}"
                      ID="${id}"
                      IssueInstant="${issueInstant}"
                      Reason="${reason}"
                      Version="2.0">
  <saml2:Issuer>${issuer}</saml2:Issuer>
  <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                SPNameQualifier="${spNameQualifier}">${nameId}</saml2:NameID>
</saml2p:LogoutRequest>`;
}
import { create } from 'xmlbuilder2';
import { v4 as uuidv4 } from 'uuid';

import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import * as fs from 'fs';
import * as xpath from 'xpath';
import * as forge from 'node-forge';

export function getSAMLRequest(
  values: string[],
  afirma: boolean,
  clavePermanente: boolean,
  pin24h: boolean,
  eidas: boolean,
  idpMovil: boolean,
  auth: boolean,
  relaystate: boolean,
  id: string,
): string {
  const issueInstant = new Date().toISOString().split('.')[0];

  const assertionConsumerServiceURL =
    process.env.ASSERTION_CONSUMER_SERVICE_URL || 'http://localhost:3000/acs';
  const providerName = process.env.SAML_PROVIDER_NAME || '21114293V_E04975701';
  const destination =
    process.env.DESTINATION ||
    'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider';
  const loa = process.env.LOA || 'http://eidas.europa.eu/LoA/low';

  const doc = create({ version: '1.0', encoding: 'UTF-8' }).ele(
    'saml2p:AuthnRequest',
    {
      'xmlns:saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
      'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      'xmlns:eidas': 'http://eidas.europa.eu/saml-extensions',
      'xmlns:saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'xmlns:eidas-natural': 'http://eidas.europa.eu/attributes/naturalperson',
      Destination: destination,
      ProviderName: providerName,
      ID: id,
      IssueInstant: issueInstant,
      AssertionConsumerServiceURL: assertionConsumerServiceURL,
      Consent: 'urn:oasis:names:tc:SAML:2.0:consent:unspecified',
      ForceAuthn: auth ? 'true' : values[0],
      IsPassive: values[1],
      Version: '2.0',
    },
  );

  // Extensions
  const extensions = doc.ele('saml2p:Extensions');
  extensions.ele('eidas:SPType').txt('public');
  const req = extensions.ele('eidas:RequestedAttributes');

  if (afirma) {
    req.ele('eidas:RequestedAttribute', {
      FriendlyName: 'AFirmaIdP',
      Name: 'http://es.minhafp.clave/AFirmaIdP',
      NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
      isRequired: 'false',
    });
  }
  if (clavePermanente) {
    req.ele('eidas:RequestedAttribute', {
      FriendlyName: 'GISSIdP',
      Name: 'http://es.minhafp.clave/GISSIdP',
      NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
      isRequired: 'false',
    });
  }
  if (pin24h) {
    req.ele('eidas:RequestedAttribute', {
      FriendlyName: 'AEATIdP',
      Name: 'http://es.minhafp.clave/AEATIdP',
      NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
      isRequired: 'false',
    });
  }
  if (eidas) {
    req.ele('eidas:RequestedAttribute', {
      FriendlyName: 'EIDASIdP',
      Name: 'http://es.minhafp.clave/EIDASIdP',
      NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
      isRequired: 'false',
    });
  }
  if (relaystate) {
    const re4 = req.ele('eidas:RequestedAttribute', {
      FriendlyName: 'RelayState',
      Name: 'http://es.minhafp.clave/RelayState',
      NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
      isRequired: 'false',
    });
    re4
      .ele('eidas:AttributeValue', {
        'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'xsi:type': 'eidas-natural:PersonIdentifierType',
      })
      .txt(uuidv4().substring(0, 8));
  }
  if (idpMovil) {
    req.ele('idpMovil:RequestedAttribute', {
      FriendlyName: 'CLVMOVILIdP',
      Name: 'http://es.minhafp.clave/CLVMOVILIdP',
      NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
      isRequired: 'false',
    });
  }

  // NameIDPolicy
  doc.ele('saml2p:NameIDPolicy', {
    AllowCreate: values[2],
    Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  });

  // RequestedAuthnContext
  const requestedAuthnContext = doc.ele('saml2p:RequestedAuthnContext', {
    Comparison: 'minimum',
  });
  requestedAuthnContext.ele('saml2:AuthnContextClassRef').txt(loa);

  const authRequestXML = doc.end({ prettyPrint: false });
  fs.writeFileSync('authRequestXML.xml', authRequestXML);

  // Devuelve el XML como string
  return doc.end({ prettyPrint: false });
}

export function signXmlFile(
  xmlString: string,
  tipo: 'login' | 'logout',
  privateKey2?: string,
  cert?: string,
  uriNode?: string,
) {
  const doc = new DOMParser().parseFromString(xmlString, 'text/xml');
  let referenceId = uriNode;

  const privateKey = fs.readFileSync('private.pem');
  const publicCert = fs.readFileSync('public.pem');

  const sig = new SignedXml({
    privateKey: privateKey,
    publicCert: publicCert,
  });

  sig.addReference({
    xpath: '/*',
    uri: '',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha512',
  });
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

  if (tipo === 'login') {
    sig.computeSignature(xmlString, {
      location: {
        reference: "//*[local-name(.)='Extensions']",
        action: 'before',
      },
    });
  } else if (tipo === 'logout') {
    sig.computeSignature(xmlString, {
      location: {
        reference: "//*[local-name(.)='NameID']",
        action: 'before',
      },
    });
  } else {
    sig.computeSignature(xmlString);
  }

  const signedXml = sig.getSignedXml();
  fs.writeFileSync('signed.xml', signedXml);
  // validateXml(signedXml);
  return signedXml;
}

export async function validateXml(xml: string): Promise<boolean> {
  try {
    const dom = new DOMParser();
    const doc = dom.parseFromString(xml, 'text/xml');
    if (!doc) {
      console.error('No se pudo parsear el XML');
      return false;
    }
    // Buscar el nodo Signature
    const signatureNodes = xpath.select(
      "//*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']",
      doc as unknown as Node,
    ) as Node[];
    if (!signatureNodes || signatureNodes.length === 0) {
      console.error('No se encontró el nodo Signature');
      return false;
    }
    const signature = signatureNodes[0];
    // Buscar el X509Certificate dentro de KeyInfo
    const certNode = xpath.select(
      ".//*[local-name()='X509Certificate']",
      signature as unknown as Node,
    ) as Node[];
    if (!certNode || certNode.length === 0) {
      console.error('No se encontró el nodo X509Certificate en KeyInfo');
      return false;
    }
    const certBase64 = certNode[0].textContent?.replace(/\s+/g, '');
    if (!certBase64) {
      console.error('El nodo X509Certificate está vacío');
      return false;
    }
    // Formatear el certificado en PEM
    const certPem =
      '-----BEGIN CERTIFICATE-----\n' +
      certBase64.match(/.{1,64}/g)?.join('\n') +
      '\n-----END CERTIFICATE-----\n';
    // Validar la firma usando xml-crypto y el cert extraído
    const sig = new SignedXml({ publicCert: certPem });
    sig.loadSignature(signature);
    const res = sig.checkSignature(xml);
    if (!res) {
      console.error('Firma inválida:', certPem);
      return false;
    }
    return true;
  } catch (err) {
    console.error('Error validando XML con X509 embebido:', err);
    return false;
  }
}
