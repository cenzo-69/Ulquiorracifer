require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
// Import fetch dynamically since node-fetch is an ES module
let fetch;

const app = express();
const PORT = process.env.PORT || 3000;

const SCOPES = ['identify', 'guilds'];

app.use(session({
  secret: process.env.SESSION_SECRET || 'keyboard cat',
  resave: false,
  saveUninitialized: false
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL,
  scope: SCOPES
}, (accessToken, refreshToken, profile, done) => {
  profile.accessToken = accessToken;
  process.nextTick(() => done(null, profile));
}));

app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

function checkAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

app.get('/login', passport.authenticate('discord'));

app.get('/callback',
  passport.authenticate('discord', { failureRedirect: '/' }),
  (req, res) => res.redirect('/dashboard')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/dashboard', checkAuth, async (req, res) => {
  try {
    // Initialize fetch if not already done
    if (!fetch) {
      const fetchModule = await import('node-fetch');
      fetch = fetchModule.default;
    }

    const userGuilds = req.user.guilds;

    // Get bot's guilds via bot token
    const botGuilds = await fetch('https://discord.com/api/v10/users/@me/guilds', {
      headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
    }).then(r => r.json());

    const botGuildIDs = botGuilds.map(g => g.id);

    // Filter ALL servers where user has Administrator permissions (0x8)
    const adminGuilds = userGuilds.filter(guild => {
      return (parseInt(guild.permissions) & 0x8) === 0x8;
    });

    // Separate servers with bot present and without bot
    const guildsWithBot = adminGuilds.filter(guild => botGuildIDs.includes(guild.id));
    const guildsWithoutBot = adminGuilds.filter(guild => !botGuildIDs.includes(guild.id));

    // Get member counts for servers where bot is present
    const guildsWithBotAndCounts = await Promise.all(
      guildsWithBot.map(async (guild) => {
        try {
          const guildData = await fetch(`https://discord.com/api/v10/guilds/${guild.id}?with_counts=true`, {
            headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
          }).then(r => r.json());
          
          return {
            ...guild,
            botPresent: true,
            onlineMembers: guildData.approximate_presence_count || 0,
            totalMembers: guildData.approximate_member_count || 0
          };
        } catch (error) {
          console.error(`Error fetching guild data for ${guild.id}:`, error);
          return {
            ...guild,
            botPresent: true,
            onlineMembers: 0,
            totalMembers: 0
          };
        }
      })
    );

    // Add servers without bot (no member counts available)
    const guildsWithoutBotFormatted = guildsWithoutBot.map(guild => ({
      ...guild,
      botPresent: false,
      onlineMembers: 0,
      totalMembers: 0
    }));

    // Combine and sort: bot present servers first
    const allGuilds = [...guildsWithBotAndCounts, ...guildsWithoutBotFormatted];

    res.render('dashboard', { user: req.user, guilds: allGuilds });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('dashboard', { user: req.user, guilds: [] });
  }
});

app.get('/manage/:guildID', checkAuth, async (req, res) => {
  const guildID = req.params.guildID;
  const userGuild = req.user.guilds.find(g => g.id === guildID);

  if (!userGuild || (parseInt(userGuild.permissions) & 0x8) !== 0x8) {
    return res.status(403).send('❌ You do not have permission to manage this server.');
  }

  try {
    // Initialize fetch if not already done
    if (!fetch) {
      const fetchModule = await import('node-fetch');
      fetch = fetchModule.default;
    }

    // Check if bot is in the server
    const botGuilds = await fetch('https://discord.com/api/v10/users/@me/guilds', {
      headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
    }).then(r => r.json());

    const botGuildIDs = botGuilds.map(g => g.id);
    const botInServer = botGuildIDs.includes(guildID);

    if (!botInServer) {
      // Redirect to bot invite link with the specific guild pre-selected
      const inviteURL = `https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&permissions=8&scope=bot&guild_id=${guildID}`;
      return res.redirect(inviteURL);
    }

    // Fetch detailed server information
    const [guildData, channels, roles] = await Promise.all([
      fetch(`https://discord.com/api/v10/guilds/${guildID}?with_counts=true`, {
        headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
      }).then(r => r.json()),
      fetch(`https://discord.com/api/v10/guilds/${guildID}/channels`, {
        headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
      }).then(r => r.json()),
      fetch(`https://discord.com/api/v10/guilds/${guildID}/roles`, {
        headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
      }).then(r => r.json())
    ]);

    // Process channel data
    const textChannels = channels.filter(c => c.type === 0);
    const voiceChannels = channels.filter(c => c.type === 2);
    const categories = channels.filter(c => c.type === 4);
    const threadChannels = channels.filter(c => [10, 11, 12].includes(c.type));
    const forumChannels = channels.filter(c => c.type === 15);
    const stageChannels = channels.filter(c => c.type === 13);

    // Process server data
    const serverInfo = {
      ...guildData,
      channelStats: {
        total: channels.length,
        text: textChannels.length,
        voice: voiceChannels.length,
        categories: categories.length,
        threads: threadChannels.length,
        forums: forumChannels.length,
        stages: stageChannels.length
      },
      roleCount: roles.length,
      boostLevel: guildData.premium_tier || 0,
      boostCount: guildData.premium_subscription_count || 0,
      features: guildData.features || [],
      verificationLevel: guildData.verification_level || 0,
      explicitContentFilter: guildData.explicit_content_filter || 0,
      mfaLevel: guildData.mfa_level || 0
    };

    res.render('manage', { 
      user: req.user, 
      guild: userGuild, 
      serverInfo: serverInfo,
      channels: channels,
      roles: roles
    });

  } catch (error) {
    console.error('Manage server error:', error);
    return res.status(500).send('❌ Error fetching server details.');
  }
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));