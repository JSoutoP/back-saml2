import { Body, Controller, Post, Req, Res, Session, Get } from '@nestjs/common';
import { Request, Response } from 'express';
import { AppService } from './app.service';
import { SamlService } from './saml/saml.service';
import { signXmlFile } from './common/helpers';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private samlService: SamlService,
  ) {}

  @Post('logout')
  async logout(@Session() session: Record<string, any>) {
    // Usar el servicio para construir el LogoutRequest
    const { xml, id, destination } =
      await this.samlService.buildSamlLogoutRequest(session);
    const signedXml = await signXmlFile(xml, 'logout');
    session.samlLogoutRequestId = id;
    const samlLogoutRequestBase64 = Buffer.from(signedXml).toString('base64');
    console.log('SAML LogoutRequest generado:', xml);
    return {
      redirectUrl: destination,
      samlLogoutRequest: samlLogoutRequestBase64,
      signedXml,
    };
  }

  @Post('login')
  async login(@Session() session: Record<string, any>) {
    const { xml, id } = await this.samlService.buildSamlRequest();
    const signedXml = await signXmlFile(xml, 'login');
    session.samlRequestId = id;
    const samlRequestBase64 = Buffer.from(signedXml).toString('base64');
    console.log('SAML AuthnRequest firmado:', signedXml);
    return {
      redirectUrl: 'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider',
      samlRequest: samlRequestBase64,
      signedXml,
    };
  }

  @Post('acs')
  async handleSamlResponse(
    @Req() req: Request,
    @Res() res: Response,
    @Body() body: any,
    @Session() session: Record<string, any>,
  ) {
    try {
      const samlResponseB64 = body.SAMLResponse;
      if (!samlResponseB64) {
        console.error('No SAMLResponse en la petición');
        return res.redirect('http://localhost:4200/error-page');
      }
      console.log('SAML Response Base64:', samlResponseB64);
      const result = await this.samlService.processSamlResponse(
        samlResponseB64,
        session,
      );
      if (!result.estado) {
        console.error('SAML Response inválida o rechazada');
        return res.redirect('http://localhost:4200/error-page');
      }

      session.samlAttributes = result.result;

      console.log('Atributos SAML extraídos:', result.result?.PersonIdentifier);

      const redirectUrl = 'http://localhost:4200/success-page';

      return res.redirect(redirectUrl);
    } catch (error) {
      console.error('Error en /acs:', error);
      return res.redirect('http://localhost:4200/error-page');
    }
  }

  @Post('acs-logout')
  async handleSamlResponseLogout(
    @Req() req: Request,
    @Res() res: Response,
    @Body() body: any,
    @Session() session: Record<string, any>,
  ) {
    try {
      const samlResponseB64 = body.logoutResponse;
      if (!samlResponseB64) {
        console.error('No SAMLResponse en la petición');
        return res.redirect('http://localhost:4200/error-page');
      }
      // console.log('SAML Response Base64:', samlResponseB64);

      const result = await this.samlService.processSamlResponseLogout(
        samlResponseB64,
        session,
      );

      if (!result.estado) {
        console.error('SAML Response Logout inválida o rechazada');
        return res.redirect('http://localhost:4200/error-page');
      }

      // HAY QUE BORRAR LA SESION DEL USUARIO

      const redirectUrl = 'http://localhost:4200';

      return res.redirect(redirectUrl);
    } catch (error) {
      console.error('Error en /acs-logout:', error);
      return res.redirect('http://localhost:4200/error-page');
    }
  }

  @Get('me')
  async getMe(@Session() session: Record<string, any>, @Res() res: Response) {
    if (session.samlAttributes) {
      return res.json({ user: session.samlAttributes });
    } else {
      return res.status(401).json({ error: 'No autenticado' });
    }
  }
}
