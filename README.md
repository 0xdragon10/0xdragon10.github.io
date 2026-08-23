# 0xdragon — official blog

Static Jekyll site, built with a custom theme (no third-party theme gem —
GitHub Pages builds it natively, no GitHub Actions needed).

## Structure

```
_config.yml           site settings
_layouts/default.html page shell: head, nav, cursor, particles, footer, shared JS
_layouts/post.html     article reading page (used automatically by every post)
_posts/                one markdown file per blog post
assets/css/main.css    all site styles
assets/js/site.js      shared JS (particles, cursor, nav, scroll animations)
assets/dragon-core.png hero/background artwork
index.html             homepage (hero, about, skills, certs, projects, writeups list, contact)
```

## Adding a new post

1. Create a file in `_posts/` named `YYYY-MM-DD-your-title.md`
   (the date in the filename controls the URL and sort order).
2. Add front matter at the top, then write the article in Markdown below it:

   ```markdown
   ---
   layout: post
   title: "Your Post Title"
   date: 2026-08-23 12:00:00 +0200
   tags: [Web Security, CTF]
   ---

   Your article content goes here, in normal Markdown.
   ```
3. Commit and push. GitHub Pages rebuilds automatically (~1 minute) and the
   post appears in the "Writeups" section on the homepage, with its own page
   at `/posts/your-title/`.

No other file needs to change to publish a new post.
