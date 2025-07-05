import { Module, MiddlewareConsumer } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { RequestLoggingMiddleware } from './request-logging.middleware';

import { SamlService } from './saml/saml.service';

@Module({
  imports: [],
  controllers: [AppController],
  providers: [AppService, SamlService],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestLoggingMiddleware).forRoutes('*');
  }
}
