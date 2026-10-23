/**
 * Sets the theme class before the first paint (no flash). An inline script is allowed by the CSP
 * only because it carries this request's nonce.
 */
export function ThemeScript({ nonce }: { nonce?: string }) {
  const code =
    "try{var t=localStorage.getItem('theme');var d=t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d)}catch(e){}";
  return <script nonce={nonce} dangerouslySetInnerHTML={{ __html: code }} />;
}
