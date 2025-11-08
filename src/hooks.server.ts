import { sequence } from '@sveltejs/kit/hooks';
import { auth } from './routes/auth.server.js';

export const handle = sequence(auth.hook);
