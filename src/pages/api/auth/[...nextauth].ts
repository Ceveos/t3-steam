import { type NextApiRequest, type NextApiResponse } from "next";
import NextAuth from "next-auth";
import { authOptions } from "~/server/auth";
import { TokenSet } from "openid-client";
import { v4 as uuidv4 } from "uuid";

interface SteamProfile {
  steamid: string;
  communityvisibilitystate: number;
  profilestate: number;
  personaname: string;
  lastlogoff: number;
  profileurl: string;
  avatar: string;
  avatarmedium: string;
  avatarfull: string;
}

interface PlayerSummaries {
  response: {
    players: SteamProfile[];
  };
}

// Since we need access to the current req and res objects, we need to define steam auth here
export default async function auth(req: NextApiRequest, res: NextApiResponse) {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return await NextAuth(req, res, {
    ...authOptions,
    providers: [
      ...authOptions.providers,
      {
        id: "steam",
        name: "Steam",
        type: "oauth",
        authorization: {
          url: "https://steamcommunity.com/openid/login",
          params: {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "checkid_setup",
            // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
            "openid.return_to": `${process.env.NEXTAUTH_URL}/api/auth/callback/steam`,
            // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
            "openid.realm": `${process.env.NEXTAUTH_URL}`,
            "openid.identity":
              "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id":
              "http://specs.openid.net/auth/2.0/identifier_select",
          },
        },
        token: {
          async request(ctx) {
            const token_params: {
              [key: string]: string | string[] | undefined;
            } = {
              "openid.assoc_handle": req.query["openid.assoc_handle"],
              "openid.signed": req.query["openid.signed"],
              "openid.sig": req.query["openid.sig"],
              "openid.ns": "http://specs.openid.net/auth/2.0",
              "openid.mode": "check_authentication",
            };
            if (
              req.query["openid.signed"] &&
              typeof req.query["openid.signed"] === "string"
            ) {
              for (const val of req.query["openid.signed"].split(",")) {
                token_params[`openid.${val}`] = req.query[`openid.${val}`];
              }
            }
            const token_url = new URL(
              "https://steamcommunity.com/openid/login"
            );
            const token_url_params = new URLSearchParams(
              token_params as unknown as Record<string, string>
            );

            token_url.search = token_url_params as unknown as string;
            const token_res = await fetch(token_url, {
              method: "POST",
              headers: {
                "Accept-language": "en\r\n",
                "Content-type": "application/x-www-form-urlencoded\r\n",
                "Content-Length": `${token_url_params.toString().length}\r\n`,
              },
              body: token_url_params.toString(),
            });
            const result = await token_res.text();
            if (
              result.match(/is_valid\s*:\s*true/i) &&
              typeof req.query["openid.claimed_id"] === "string"
            ) {
              const matches = req.query["openid.claimed_id"].match(
                /^https:\/\/steamcommunity.com\/openid\/id\/([0-9]{17,25})/
              );
              if (!matches || matches.length < 2)
                return { tokens: new TokenSet({}) };

              const steamId = matches[1]?.match(/^-?\d+$/) ? matches[1] : 0;
              const tokenset = new TokenSet({
                // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
                id_token: uuidv4(),
                // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
                access_token: uuidv4(),
                id: steamId,
              });
              return { tokens: tokenset };
            } else {
              throw new Error("Invalid Steam login");
            }
          },
        },
        userinfo: {
          async request(ctx) {
            if (!ctx.tokens.id) {
              throw new Error("Steam ID not provided");
            }

            const user_result = await fetch(
              // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
              `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${ctx.provider.clientSecret}&steamids=${ctx.tokens.id}`
            );
            const json = (await user_result.json()) as PlayerSummaries;

            if (!json.response.players[0]) {
              throw new Error("Steam player information not found");
            }

            // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-explicit-any
            return json.response.players[0] as unknown as any;
          },
        },
        idToken: false,
        checks: ["none"],
        profile(profile: SteamProfile) {
          return {
            id: profile.steamid,
            image: profile.avatarfull,
            name: profile.personaname,
          };
        },
        clientId: "not-used",
        clientSecret: process.env.STEAM_API,
      },
    ],
  });
}
