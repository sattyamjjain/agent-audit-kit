import { connect } from './client';

export function handler(req: any) {
  return connect(req.body);
}
