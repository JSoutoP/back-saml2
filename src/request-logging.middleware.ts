import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { Logger } from '@nestjs/common';

const logger = new Logger();
@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const start = Date.now();

    res.on('finish', () => {
      const elapsed = Date.now() - start;

      const texto_log = `[${req.constructor.name}] Ip: ${req.ip} - Request: ${req.method} ${req.originalUrl} - Status: ${res.statusCode} - Response Time: ${elapsed}ms`;

      logger.log(
        `Ip: ${req.ip} - Request: ${req.method} ${req.originalUrl} - Status: ${res.statusCode} - Response Time: ${elapsed}ms`,
        req.constructor.name,
      );
    });
    next();
  }
}
