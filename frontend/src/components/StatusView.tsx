type StatusViewProps =
  | { variant: "loading" }
  | { variant: "investigating"; target: string }
  | { variant: "error"; target: string; message: string; onRetry: () => void };

/**
 * Covers every non-ready state the dashboard can be in. Kept as one
 * component (rather than three) because they share the same visual family
 * -- a centered card -- and only differ in copy/controls.
 */
export function StatusView(props: StatusViewProps) {
  return (
    <div className="centered-message">
      <div className="centered-message-box">{renderBody(props)}</div>
    </div>
  );
}

function renderBody(props: StatusViewProps) {
  switch (props.variant) {
    case "loading":
      return <p>Loading investigation data…</p>;

    case "investigating":
      return (
        <>
          <p className="status-view-eyebrow">Investigating</p>
          <p className="status-view-target">{props.target}</p>
          <p className="status-view-detail">Resolving DNS records…</p>
          <div className="indeterminate-bar" role="progressbar" aria-label="Investigation in progress">
            <div className="indeterminate-bar-fill" />
          </div>
        </>
      );

    case "error":
      return (
        <>
          <p className="status-view-eyebrow status-view-eyebrow-error">Investigation failed</p>
          <p className="status-view-target">{props.target}</p>
          <p className="status-view-detail">{props.message}</p>
          <button className="status-view-retry" onClick={props.onRetry}>
            Retry
          </button>
        </>
      );
  }
}
