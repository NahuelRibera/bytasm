import { BinaryArt } from "../art/BinaryArt";
import { Link } from "../router";

export function NotFound() {
  return (
    <div className="not-found">
      <BinaryArt character="nohead" variant="field" tint="ash" />
      <p className="code" aria-hidden="true">404</p>
      <h1>Not found</h1>
      <p className="lede">
        Nothing lives at this address. <Link to="/">Back to projects</Link>
      </p>
    </div>
  );
}
