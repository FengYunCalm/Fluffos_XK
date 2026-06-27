import { defineConfig } from 'vitepress'
import SIDEBAR from "./sidebar";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  lang: 'en-US',
  title: "FluffOS_XK Docs",
  description: "Production-oriented FluffOS_XK engine documentation",
  lastUpdated: true,
  sitemap: {
    hostname: 'https://www.fluffos.info'
  },
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Github', link: 'https://github.com/FengYunCalm/Fluffos_XK' }
    ],
    sidebar: SIDEBAR,
    search: {
      provider: 'local',
      options: {
        miniSearch: {
          /**
           * @type {Pick<import('minisearch').Options, 'extractField' | 'tokenize' | 'processTerm'>}
           */
          options: {
          },
          /**
           * @type {import('minisearch').SearchOptions}
           * @default
           * { fuzzy: 0.2, prefix: true, boost: { title: 4, text: 2, titles: 1 } }
           */
          searchOptions: {
            fuzzy: 0.1,
            prefix: true,
            fields: [ 'relativePath', 'title' ],
            boost: {
              title: 4,
              text: 2,
              titles: 1
            }
          }
        }
      }
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/FengYunCalm/Fluffos_XK' }
    ],
    editLink: {
      pattern: 'https://github.com/FengYunCalm/Fluffos_XK/edit/master/docs/:path'
    },
  }
})
