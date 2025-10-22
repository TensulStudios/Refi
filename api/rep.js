export default async function handler(req, res) {
  const { url } = req.query;
  if (!url) {
    return res.status(400).send("Missing ?url= parameter");
  }

  try {
    if (!/^https?:\/\//.test(url)) {
      return res.status(400).send("Invalid URL");
    }

    const response = await fetch(url);
    const html = await response.text();

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");

    res.status(200).send(html);
  } catch (err) {
    res.status(500).send("Error fetching site: " + err.message);
  }
}
