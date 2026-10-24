import type { DefaultTreeAdapterTypes } from 'parse5';

export type VendorFeed = 'nodejs' | 'python' | 'php';
type HtmlNode = DefaultTreeAdapterTypes.Node;

/** Fixed official feeds; article extraction is opt-in for each vendor. */
export const VENDOR_FEEDS = {
  nodejs: { feed: 'https://nodejs.org/en/feed/vulnerability.xml', origin: 'https://nodejs.org' },
  python: { feed: 'https://blog.python.org/rss.xml', origin: 'https://blog.python.org' },
  php: { feed: 'https://www.php.net/feed.atom', origin: 'https://www.php.net' },
} as const;

export function vendorArticleTarget(
  vendor: VendorFeed,
  value: string,
): { url: string; anchor?: string } | undefined {
  try {
    const url = new URL(value);
    if (url.origin !== VENDOR_FEEDS[vendor].origin || url.username || url.password || url.search)
      return undefined;
    if (vendor === 'nodejs' && !/^\/en\/blog\/vulnerability\/[a-z0-9-]+\/?$/.test(url.pathname))
      return undefined;
    if (vendor === 'python' && !/^\/\d{4}\/\d{2}\/[a-z0-9-]+(?:\.html|\/)$/.test(url.pathname))
      return undefined;
    if (vendor === 'php') {
      if (
        !/^\/(?:index\.php|archive\/\d{4}\.php)$/.test(url.pathname) ||
        !/^#\d{4}-\d{2}-\d{2}-\d+$/.test(url.hash)
      )
        return undefined;
      const anchor = url.hash.slice(1);
      url.hash = '';
      return { url: url.href, anchor };
    }
    if (url.hash) return undefined;
    return { url: url.href };
  } catch {
    return undefined;
  }
}

export function vendorArticleBody(
  vendor: VendorFeed,
  nodes: Iterable<HtmlNode>,
  anchor?: string,
): HtmlNode | undefined {
  const complete = (node: HtmlNode) =>
    'tagName' in node &&
    node.namespaceURI === 'http://www.w3.org/1999/xhtml' &&
    node.sourceCodeLocation?.startTag &&
    node.sourceCodeLocation.endTag;
  const classes = (node: DefaultTreeAdapterTypes.Element) =>
    (node.attrs.find((attr) => attr.name === 'class')?.value ?? '').split(/\s+/);
  for (const node of nodes) {
    if (!('tagName' in node) || node.namespaceURI !== 'http://www.w3.org/1999/xhtml') continue;
    if (
      vendor === 'nodejs' &&
      node.tagName === 'main' &&
      node.attrs.some((attr) => attr.name === 'id' && attr.value === 'main')
    )
      return complete(node) ? node : undefined;
    if (vendor === 'python' && node.tagName === 'article' && classes(node).includes('prose'))
      return complete(node) ? node : undefined;
    if (vendor === 'php' && node.attrs.some((attr) => attr.name === 'id' && attr.value === anchor)) {
      let parent: HtmlNode | undefined = node;
      for (
        let depth = 0;
        parent && depth < 8;
        depth++, parent = 'parentNode' in parent ? (parent.parentNode ?? undefined) : undefined
      )
        if ('tagName' in parent && parent.tagName === 'article' && classes(parent).includes('newsentry'))
          return complete(parent) ? parent : undefined;
      return undefined;
    }
  }
  return undefined;
}
