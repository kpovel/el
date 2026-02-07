import type { ReactNode } from "react";

export function Layout({
  children,
  title,
  styles,
  bodyClass,
}: {
  children: ReactNode;
  title: string;
  styles?: string;
  bodyClass?: string;
}) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://unpkg.com/htmx.org@2.0.4"></script>
        {styles && <style dangerouslySetInnerHTML={{ __html: styles }} />}
      </head>
      <body className={bodyClass}>{children}</body>
    </html>
  );
}
