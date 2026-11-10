export interface Tag {
  tag: string;
  attrs: Record<string, string>;
}

/** Every tag of these names, with attribute names lowercased. Regex based, so it tolerates broken markup. */
export function tags(html: string, names: string): Tag[] {
  const out: Tag[] = [];
  const pattern = new RegExp(`<(${names})\\b([^>]*)>`, 'gi');
  for (const match of html.matchAll(pattern)) {
    const attrs: Record<string, string> = {};
    for (const a of match[2].matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
      attrs[a[1].toLowerCase()] = (a[2] ?? a[3] ?? a[4] ?? '').replace(/&amp;/g, '&').trim();
    }
    out.push({ tag: match[1].toLowerCase(), attrs });
  }
  return out;
}

export function resolveUrl(value: string, base: string): URL | null {
  if (!value || /^(javascript|mailto|tel|data|blob|about):/i.test(value)) return null;
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

const bareHost = (url: URL): string => url.hostname.replace(/^www\./, '');
export const sameSite = (url: URL, site: URL): boolean => bareHost(url) === bareHost(site);

/** CDNs that serve fixed files, so an integrity hash is possible and expected. */
export const STATIC_CDNS = /^(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|ajax\.googleapis\.com|ajax\.aspnetcdn\.com|(stackpath|maxcdn|netdna)\.bootstrapcdn\.com|cdn\.datatables\.net|use\.fontawesome\.com|cdn\.rawgit\.com|cdn\.statically\.io)$/i;

/** Large vendors whose scripts are theirs, not the site's, so their contents say nothing about this site. */
export const VENDOR_HOSTS = /(^|\.)(google|googleapis|gstatic|googletagmanager|google-analytics|doubleclick|facebook|facebook\.net|fbcdn|twitter|x|licdn|linkedin|hotjar|clarity\.ms|cloudflareinsights|cloudflare|stripe|paypal|recaptcha|youtube|vimeo|hubspot|intercom|zendesk|tawk|crisp|botpress|segment|mixpanel|sentry-cdn|newrelic|nr-data|bing|yandex|tiktok|pinterest|addthis|sharethis|disqus|jsdelivr|unpkg|cdnjs|jquery|bootstrapcdn|fontawesome)\.(com|net|io|ms|cloud|org|ru)$/i;
