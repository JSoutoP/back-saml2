export class RequestSAMLDTO {
  providerName: string;
  url: string;
  returnURL: string;
  application: string;
  forceCheck: boolean;
  eidasloa: string;
  nameIDPolicy: string;
  afirmaCheck: boolean;
  gissCheck: boolean;
  aeatCheck: boolean;
  eidasCheck: boolean;
  mobileCheck: boolean;
  relayState?: string;
  SAMLRequest?: string;
  logoutRequest?: string;
}
