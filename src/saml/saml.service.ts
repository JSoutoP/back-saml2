import { Injectable } from '@nestjs/common';
import { IdentityProvider } from 'samlify/types/src/entity-idp';
import { ServiceProvider } from 'samlify/types/src/entity-sp';
import { v4 as uuidv4 } from 'uuid';
import { RequestSAMLDTO } from 'src/dto/request-saml-dto';
import { getSAMLRequest, getSAMLLogout, validateXml } from 'src/common/helpers';
import { DOMParser } from '@xmldom/xmldom';

@Injectable()
export class SamlService {
  private sp: ServiceProvider;
  private idp: IdentityProvider;

  constructor() {}

  async buildSamlRequest(requestSAML?: RequestSAMLDTO) {
    const id = '_' + uuidv4();
    const xml = getSAMLRequest(
      [
        'true',
        'false',
        'true',
        'false',
        'false',
        'false',
        'false',
        'false',
        'true',
        'true',
        'false',
        'false',
        'false',
        'false',
        'false',
        'false',
        'false',
        'true',
        'true',
        'true',
        'false',
        'true',
        'false',
      ],
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      id,
    );

    return { xml, id };
  }

  async buildSamlLogoutRequest(session: Record<string, any>) {
    const id = '_' + uuidv4();
    const issueInstant = new Date().toISOString();
    const issuer =
      process.env.SAML_LOGOUT_ISSUER || 'http://localhost:3000/acs-logout';
    const nameId =
      session.samlAttributes?.PersonIdentifier ||
      process.env.SAML_LOGOUT_NAMEID ||
      '21114293V_E04975701';
    const spNameQualifier =
      process.env.SAML_LOGOUT_SP_NAME_QUALIFIER || 'http://localhost:3000/acs';

    const reason = 'urn:oasis:names:tc:SAML:2.0:logout:user';
    const xml = getSAMLLogout(
      id,
      issueInstant,
      nameId,
      spNameQualifier,
      issuer,
      reason,
    );
    const destination =
      process.env.DESTINATION ||
      'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider';
    return { xml, id, destination };
  }

  async processSamlResponseLogout(
    samlResponseB64: string,
    session: Record<string, any>,
  ) {
    try {
      const decodedXml = Buffer.from(samlResponseB64, 'base64').toString(
        'utf-8',
      );

      const isValid = validateXml(decodedXml);
      if (!isValid) {
        throw new Error('Firma SAMLResponse inválida');
      }

      const doc = new DOMParser().parseFromString(decodedXml, 'text/xml');
      const statusNode = doc.getElementsByTagName('saml2p:StatusMessage')[0];
      const status = statusNode?.textContent;
      if (status !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        throw new Error('Estado de SAML no exitoso: ' + status);
      }
      const conditions = doc.getElementsByTagName('saml2:Conditions')[0];
      const notBefore = conditions?.getAttribute('NotBefore');
      const notAfter = conditions?.getAttribute('NotOnOrAfter');
      const now = new Date().getTime();
      const clockSkew = 5 * 60 * 1000;
      if (notBefore && new Date(notBefore).getTime() - clockSkew > now) {
        throw new Error(`NotBefore inválido: ${notBefore}`);
      }
      if (notAfter && new Date(notAfter).getTime() + clockSkew < now) {
        throw new Error(`NotOnOrAfter inválido: ${notAfter}`);
      }
      const inResponseTo = doc.documentElement!.getAttribute('InResponseTo');
      const expectedId = session?.samlRequestId;
      if (expectedId && inResponseTo && expectedId !== inResponseTo) {
        throw new Error(
          `InResponseTo mismatch: esperado ${expectedId}, recibido ${inResponseTo}`,
        );
      }

      session.result = 'success';

      return { estado: session.result };
    } catch (error) {
      console.error('Error procesando SAMLResponse en Logout:', error);
      session.result = 'fail';
      return { estado: session.result, error: error.message };
    }
  }

  async processSamlResponse(
    samlResponseB64: string,
    session: Record<string, any>,
  ) {
    try {
      const decodedXml = Buffer.from(samlResponseB64, 'base64').toString(
        'utf-8',
      );

      const isValid = validateXml(decodedXml);
      if (!isValid) {
        throw new Error('Firma SAMLResponse inválida');
      }

      const doc = new DOMParser().parseFromString(decodedXml, 'text/xml');
      const statusNode = doc.getElementsByTagName('saml2p:StatusMessage')[0];
      const status = statusNode?.textContent;
      if (status !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        throw new Error('Estado de SAML no exitoso: ' + status);
      }
      const conditions = doc.getElementsByTagName('saml2:Conditions')[0];
      const notBefore = conditions?.getAttribute('NotBefore');
      const notAfter = conditions?.getAttribute('NotOnOrAfter');
      const now = new Date().getTime();
      const clockSkew = 5 * 60 * 1000;
      if (notBefore && new Date(notBefore).getTime() - clockSkew > now) {
        throw new Error(`NotBefore inválido: ${notBefore}`);
      }
      if (notAfter && new Date(notAfter).getTime() + clockSkew < now) {
        throw new Error(`NotOnOrAfter inválido: ${notAfter}`);
      }
      const inResponseTo = doc.documentElement!.getAttribute('InResponseTo');
      const expectedId = session?.samlRequestId;
      if (expectedId && inResponseTo && expectedId !== inResponseTo) {
        throw new Error(
          `InResponseTo mismatch: esperado ${expectedId}, recibido ${inResponseTo}`,
        );
      }
      // === Extraer atributos del Assertion ===
      const attributeMap: Record<string, string> = {};
      const attributeNodes = doc.getElementsByTagName('saml2:Attribute');
      for (let i = 0; i < attributeNodes.length; i++) {
        const attr = attributeNodes[i];
        const name = attr.getAttribute('FriendlyName');
        const valueNode = attr.getElementsByTagName('saml2:AttributeValue')[0];
        const value = valueNode?.textContent?.trim();
        if (name && value) {
          attributeMap[name] = value;
        }
      }
      const result = {
        FamilyName: attributeMap['FamilyName'] || null,
        FirstName: attributeMap['FirstName'] || null,
        PersonIdentifier: attributeMap['PersonIdentifier'] || null,
        PartialFirma: attributeMap['PartialAfirma'] || null,
        SelectedIdP: attributeMap['SelectedIdP'] || null,
        FirstSurname: attributeMap['FirstSurname'] || null,
      };
      session.samlResponse = decodedXml;
      session.attributes = result;
      session.result = 'success';
      // console.log('Atributos extraídos:', result);
      return { estado: session.result, result };
    } catch (error) {
      console.error('Error procesando SAMLResponse:', error);
      session.result = 'fail';
      return { estado: session.result, error: error.message };
    }
  }
}
