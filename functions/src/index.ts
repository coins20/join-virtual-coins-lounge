import * as functions from 'firebase-functions';
import fetch from 'node-fetch';
import FormData from 'form-data';
import * as crypto from 'crypto';

function ensureAuthenticated(context: functions.https.CallableContext) {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Authentication required');
  }
  if (!context.auth.token.email) {
    throw new functions.https.HttpsError('unauthenticated', 'no email address');
  }
  if (!context.auth.token.email_verified) {
    throw new functions.https.HttpsError('unauthenticated', 'not verified');
  }
  if (!context.auth.token.email.match(/@[a-z]+\.tsukuba\.ac\.jp$/)) {
    throw new functions.https.HttpsError('unauthenticated', 'invalid email address');
  }
}

export const getDiscordAuthURL = functions.https.onCall((data, context) => {
  ensureAuthenticated(context);

  const clientID = functions.config().discord.client_id;
  const redirectURI = functions.config().discord.redirect_uri;
  const state = crypto.randomBytes(22).toString('hex');
  const href = 'https://discordapp.com/api/oauth2/authorize?response_type=code&client_id='+clientID+'&scope=identify%20guilds.join&state='+state+'&redirect_uri='+redirectURI+'&prompt=consent';
  return {
    href: href,
    state: state,
  };
});

export const authDiscord = functions.https.onCall(async (data, context) => {
  ensureAuthenticated(context);
  console.log(context.auth);

  const body = new FormData();
  body.append('client_id', functions.config().discord.client_id);
  body.append('client_secret', functions.config().discord.client_secret);
  body.append('grant_type', 'authorization_code')
  body.append('code', data.code);
  body.append('redirect_uri', functions.config().discord.redirect_uri);
  body.append('scope', 'identify');

  const tokenResult = await fetch('https://discordapp.com/api/v6/oauth2/token', { method: 'POST', body: body });
  const tokenResponse = await tokenResult.json();
  if (tokenResult.status !== 200) {
    console.error(`${tokenResult.status} ${tokenResult.status}: ${JSON.stringify(tokenResponse)}`);
    throw new functions.https.HttpsError('internal', 'Failed to retreive token');
  }

  const userResult = await fetch('https://discordapp.com/api/v6/users/@me', {
    headers: {
      'Authorization': 'Bearer ' + tokenResponse.access_token
    }
  });
  const userResponse = await userResult.json();
  if (userResult.status !== 200) {
    console.error(`${userResult.status} ${userResult.status}: ${JSON.stringify(userResponse)}`);
    throw new functions.https.HttpsError('internal', 'Failed to retreive user');
  }
  console.log(userResponse);

  const joinResult = await fetch(`https://discordapp.com/api/v6/guilds/${functions.config().discord.guild_id}/members/${userResponse.id}`, {
    method: 'PUT',
    headers: {
      'Authorization': 'Bot ' + functions.config().discord.bot_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ access_token: tokenResponse.access_token, roles: [] }),
  });
  if (joinResult.status !== 201 && joinResult.status !== 204) {
    console.error(`${joinResult.status} ${joinResult.status}`);
    console.error(await joinResult.text());
    throw new functions.https.HttpsError('internal', 'Failed to add member');
  }

  await fetch(functions.config().discord.notify_webhook_url, { method: 'POST', body: JSON.stringify({ content: `\`${context.auth?.token.email}\` joined as ${userResponse.username}#${userResponse.discriminator} (${userResponse.id})` }), headers: { 'Content-Type': 'application/json' } })

  return {
    discord_name: userResponse.username + '#' + userResponse.discriminator
  };
});
